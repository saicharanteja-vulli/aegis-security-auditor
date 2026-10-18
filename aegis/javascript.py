"""Syntax-tree review leads with bounded, sequential local alias tracking.

Tree-sitter parses source only. This is not a type resolver, execution engine,
whole-program dataflow analysis, or proof of vulnerability reachability.
"""
from pathlib import PurePosixPath
import re
from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

LANGUAGES={
    'js':Language(tree_sitter_javascript.language()),
    'ts':Language(tree_sitter_typescript.language_typescript()),
    'tsx':Language(tree_sitter_typescript.language_tsx()),
}
CHILD='node:child_process'
UNKNOWN=None


def text(node): return node.text.decode('utf-8') if node else ''
def field(node,name): return node.child_by_field_name(name) if node else None


def names(pattern):
    if pattern is None: return []
    if pattern.type in {'identifier','shorthand_property_identifier_pattern'}: return [text(pattern)]
    if pattern.type=='pair_pattern': return names(field(pattern,'value'))
    if pattern.type in {'assignment_pattern','object_assignment_pattern'}: return names(field(pattern,'left'))
    if pattern.type in {'required_parameter','optional_parameter'}: return names(field(pattern,'pattern'))
    if pattern.type in {'object_pattern','array_pattern','rest_pattern','formal_parameters'}:
        return [name for child in pattern.named_children for name in names(child)]
    return []


class JavaScriptReview:
    def __init__(self): self.env={};self.findings=[]

    def qualified(self,node):
        if node is None: return UNKNOWN
        if node.type in {'parenthesized_expression','as_expression','non_null_expression','satisfies_expression'}:
            return self.qualified(node.named_children[0]) if node.named_children else UNKNOWN
        if node.type=='identifier':
            name=text(node)
            return self.env.get(name,{'eval':'eval','Function':'Function','require':'require','child_process':CHILD}.get(name))
        if node.type in {'member_expression','subscript_expression'}:
            base=self.qualified(field(node,'object'))
            prop=field(node,'property') or field(node,'index')
            name=self.property_name(prop)
            return base+'.'+name if base and name else UNKNOWN
        if node.type=='call_expression' and self.qualified(field(node,'function'))=='require':
            arguments=field(node,'arguments')
            items=arguments.named_children if arguments else []
            if len(items)==1 and self.property_name(items[0]) in {'child_process',CHILD}: return CHILD
        return UNKNOWN

    def property_name(self,node):
        if node and node.type in {'property_identifier','identifier','shorthand_property_identifier_pattern'}: return text(node)
        if node and node.type=='string':
            # Deliberately only plain literal names, never eval/decode source.
            value=text(node)[1:-1]
            return value if '\\' not in value else None
        return None

    def bind(self,pattern,value):
        if not pattern: return
        if pattern.type=='identifier': self.env[text(pattern)]=value
        elif pattern.type=='object_pattern':
            for item in pattern.named_children:
                if item.type=='pair_pattern':
                    key=self.property_name(field(item,'key'))
                    self.bind(field(item,'value'),value+'.'+key if value and key else UNKNOWN)
                elif item.type=='shorthand_property_identifier_pattern':
                    name=text(item);self.env[name]=value+'.'+name if value else UNKNOWN
                else:
                    for name in names(item): self.env[name]=UNKNOWN
        else:
            for name in names(pattern): self.env[name]=UNKNOWN

    def add(self,rule,node): self.findings.append((rule,node.start_point.row+1,'medium'))

    def visit(self,node):
        handler=getattr(self,'visit_'+node.type,None)
        if handler: handler(node)
        else:
            for child in node.named_children: self.visit(child)

    def visit_import_statement(self,node):
        source=self.property_name(field(node,'source'))
        module=CHILD if source in {CHILD,'child_process'} else UNKNOWN
        clause=next((child for child in node.named_children if child.type=='import_clause'),None)
        if not clause: return
        for child in clause.named_children:
            if child.type=='identifier': self.env[text(child)]=module
            elif child.type=='namespace_import':
                for name in child.named_children: self.env[text(name)]=module
            elif child.type=='named_imports':
                for spec in child.named_children:
                    imported=field(spec,'name');alias=field(spec,'alias') or imported
                    self.env[text(alias)]=module+'.'+text(imported) if module else UNKNOWN

    def visit_variable_declarator(self,node):
        value=field(node,'value')
        if value: self.visit(value)
        self.bind(field(node,'name'),self.qualified(value))

    def visit_assignment_expression(self,node):
        left=field(node,'left');right=field(node,'right')
        if right: self.visit(right)
        if left and left.type in {'member_expression','subscript_expression'}:
            prop=field(left,'property') or field(left,'index')
            if self.property_name(prop)=='innerHTML': self.add('JS001',prop)
            self.visit(left)
        else: self.bind(left,self.qualified(right))

    def visit_augmented_assignment_expression(self,node):
        # Compound mutation invalidates a known local alias.
        for child in node.named_children: self.visit(child)
        self.bind(field(node,'left'),UNKNOWN)

    def visit_call_expression(self,node):
        fn=field(node,'function');qualified=self.qualified(fn)
        if qualified=='eval': self.add('JS002',node)
        if qualified in {CHILD+'.exec',CHILD+'.execSync'}: self.add('JS003',node)
        for child in node.named_children: self.visit(child)

    def visit_new_expression(self,node):
        if self.qualified(field(node,'constructor'))=='Function': self.add('JS002',node)
        for child in node.named_children: self.visit(child)

    def visit_jsx_attribute(self,node):
        if node.named_children and text(node.named_children[0])=='dangerouslySetInnerHTML' and len(node.named_children)>1:
            self.add('JS001',node)
        for child in node.named_children: self.visit(child)

    def visit_function(self,node):
        name=field(node,'name')
        if name: self.env[text(name)]=UNKNOWN
        outer=self.env;self.env=dict(outer)
        parameters=field(node,'parameters') or field(node,'parameter')
        for name in names(parameters): self.env[name]=UNKNOWN
        # Preserve executable default expressions, which ordinary traversal sees.
        if parameters: self.visit(parameters)
        body=field(node,'body')
        if body: self.visit(body)
        self.env=outer
    visit_function_declaration=visit_function
    visit_generator_function_declaration=visit_function
    visit_function_expression=visit_function
    visit_generator_function=visit_function
    visit_arrow_function=visit_function
    visit_method_definition=visit_function

    def visit_statement_block(self,node):
        # Block-scoped declarations shadow imports only inside this block.
        outer=dict(self.env);local=set()
        for statement in node.named_children:
            if statement.type=='lexical_declaration':
                for declaration in statement.named_children: local.update(names(field(declaration,'name')))
            elif statement.type in {'class_declaration','function_declaration','generator_function_declaration'}:
                name=field(statement,'name')
                if name: local.add(text(name))
        for name in local: self.env[name]=UNKNOWN
        for child in node.named_children: self.visit(child)
        for name in local:
            if name in outer: self.env[name]=outer[name]
            else: self.env.pop(name,None)

    def visit_if_statement(self,node):
        condition=field(node,'condition')
        if condition: self.visit(condition)
        original=dict(self.env)
        consequence=field(node,'consequence')
        if consequence: self.visit(consequence)
        yes=dict(self.env);self.env=dict(original)
        alternative=field(node,'alternative')
        if alternative: self.visit(alternative)
        no=self.env
        self.env={name:yes.get(name) if yes.get(name)==no.get(name) else UNKNOWN for name in yes.keys()|no.keys()}


def javascript_review(source,path='source.js'):
    suffix=PurePosixPath(path).suffix.lower()
    if suffix=='.html':
        findings=[];warnings=['HTML review covers inline script blocks only; event handlers and external scripts are not analyzed.']
        for match in re.finditer(r'<script\b[^>]*>([\s\S]*?)</script\s*>',source,re.I):
            leads,notes=javascript_review(match[1],'inline.js')
            offset=source.count('\n',0,match.start(1))
            findings.extend((rule,line+offset,confidence) for rule,line,confidence in leads);warnings.extend(notes)
        return sorted(set(findings)),warnings
    grammar='tsx' if suffix=='.tsx' else 'ts' if suffix=='.ts' else 'js'
    root=Parser(LANGUAGES[grammar]).parse(source.encode('utf-8')).root_node
    if root.has_error:
        return [],['JavaScript/TypeScript parsing failed; only text-based secret/key checks ran.']
    reviewer=JavaScriptReview();reviewer.visit(root)
    return sorted(set(reviewer.findings),key=lambda item:(item[1],item[0])),[]
