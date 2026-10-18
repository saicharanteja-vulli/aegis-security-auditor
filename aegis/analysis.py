"""Bounded local syntax analysis, not whole-program taint analysis."""
import ast
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Binding:
    alias: str | None = None
    constant: bool = False
    value: object = None


UNKNOWN = Binding()


class Locals(ast.NodeVisitor):
    def __init__(self): self.names=set()
    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Store): self.names.add(node.id)
    def visit_FunctionDef(self,node): self.names.add(node.name)
    visit_AsyncFunctionDef=visit_FunctionDef
    def visit_ClassDef(self,node): self.names.add(node.name)
    def visit_Lambda(self,node): pass
    def visit_Import(self,node):
        self.names.update(item.asname or item.name.split('.')[0] for item in node.names)
    def visit_ImportFrom(self,node):
        self.names.update(item.asname or item.name for item in node.names)


class PythonReview(ast.NodeVisitor):
    def __init__(self):
        self.env={};self.findings=[]

    def qualified(self,node):
        if isinstance(node,ast.Name):
            return self.env[node.id].alias if node.id in self.env else (node.id if node.id in {'eval','exec'} else None)
        if isinstance(node,ast.Attribute):
            base=self.qualified(node.value)
            return base+'.'+node.attr if base else None
        return None

    def value(self,node):
        if isinstance(node,ast.Name): return self.env.get(node.id,Binding(self.qualified(node)))
        if isinstance(node,ast.Constant): return Binding(constant=True,value=node.value)
        if isinstance(node,ast.Attribute): return Binding(alias=self.qualified(node))
        if isinstance(node,ast.JoinedStr):
            values=[self.value(item.value) if isinstance(item,ast.FormattedValue) else self.value(item) for item in node.values]
            return Binding(constant=all(v.constant for v in values))
        if isinstance(node,ast.BinOp):
            return Binding(constant=self.value(node.left).constant and self.value(node.right).constant)
        if isinstance(node,ast.Call):
            if self.qualified(node.func)=='flask.Flask': return Binding(alias='flask.instance')
            if isinstance(node.func,ast.Attribute) and node.func.attr=='format':
                return Binding(constant=self.value(node.func.value).constant and
                               all(self.value(arg).constant for arg in node.args) and
                               all(self.value(kw.value).constant for kw in node.keywords))
        return UNKNOWN

    def assign(self,target,binding):
        if isinstance(target,ast.Name): self.env[target.id]=binding
        elif isinstance(target,(ast.Tuple,ast.List)):
            for item in target.elts: self.assign(item,UNKNOWN)

    def visit_Import(self,node):
        for item in node.names:
            self.env[item.asname or item.name.split('.')[0]]=Binding(alias=item.name if item.asname else item.name.split('.')[0])

    def visit_ImportFrom(self,node):
        for item in node.names: self.env[item.asname or item.name]=Binding(alias=f'{node.module}.{item.name}')

    def visit_Assign(self,node):
        self.visit(node.value)
        value=self.value(node.value)
        for target in node.targets: self.assign(target,value)

    def visit_AnnAssign(self,node):
        if node.value: self.visit(node.value)
        self.assign(node.target,self.value(node.value) if node.value else UNKNOWN)

    def visit_AugAssign(self,node):
        self.visit(node.value)
        self.assign(node.target,UNKNOWN)

    def visit_FunctionDef(self,node):
        for expression in [*node.decorator_list,*node.args.defaults,*[v for v in node.args.kw_defaults if v]]: self.visit(expression)
        self.env[node.name]=UNKNOWN
        outer=self.env
        self.env=dict(outer)
        local=Locals()
        for statement in node.body: local.visit(statement)
        parameters=[*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]
        if node.args.vararg: parameters.append(node.args.vararg)
        if node.args.kwarg: parameters.append(node.args.kwarg)
        for name in local.names | {arg.arg for arg in parameters}: self.env[name]=UNKNOWN
        for statement in node.body: self.visit(statement)
        self.env=outer
    visit_AsyncFunctionDef=visit_FunctionDef

    def visit_Lambda(self,node):
        outer=self.env;self.env=dict(outer)
        for arg in [*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]: self.env[arg.arg]=UNKNOWN
        self.visit(node.body);self.env=outer

    def visit_ClassDef(self,node):
        self.env[node.name]=UNKNOWN
        outer=self.env;self.env=dict(outer)
        for statement in node.body: self.visit(statement)
        self.env=outer

    def visit_If(self,node):
        self.visit(node.test)
        original=dict(self.env)
        for statement in node.body: self.visit(statement)
        yes=dict(self.env);self.env=dict(original)
        for statement in node.orelse: self.visit(statement)
        no=self.env
        self.env={key:yes.get(key,UNKNOWN) if yes.get(key,UNKNOWN)==no.get(key,UNKNOWN) else UNKNOWN for key in yes.keys()|no.keys()}

    def visit_For(self,node):
        original=dict(self.env);self.visit(node.iter);self.assign(node.target,UNKNOWN)
        for statement in [*node.body,*node.orelse]: self.visit(statement)
        self.env={key:value if original.get(key,UNKNOWN)==value else UNKNOWN for key,value in self.env.items()}
    visit_AsyncFor=visit_For

    def visit_Call(self,node):
        fn=self.qualified(node.func) or ''
        kw={item.arg:self.value(item.value) for item in node.keywords}
        yes=lambda key: key in kw and kw[key].constant and kw[key].value is True
        no=lambda key: key in kw and kw[key].constant and kw[key].value is False
        add=lambda rule,confidence='medium': self.findings.append((rule,node.lineno,confidence))
        if fn in {'os.system','os.popen'} or (fn.startswith('subprocess.') and yes('shell')): add('PY001','high')
        if fn in {'eval','exec','builtins.eval','builtins.exec'}: add('PY002','high')
        if isinstance(node.func,ast.Attribute) and node.func.attr in {'execute','executemany'} and node.args and not self.value(node.args[0]).constant:
            add('PY003')
        if fn in {'pickle.load','pickle.loads','dill.load','dill.loads'}: add('PY004','high')
        if no('verify') and fn.startswith(('requests.','httpx.')): add('PY005','high')
        if yes('debug') and (fn=='flask.instance.run' or isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='app' and node.func.attr=='run'):
            add('PY006','medium')
        self.generic_visit(node)


def python_findings(source):
    reviewer=PythonReview();reviewer.visit(ast.parse(source));return reviewer.findings


def javascript_mask(source,strings=True):
    """Length-preserving lexical mask; deliberately not a JavaScript parser."""
    output=list(source);index=0
    def blank(start,end):
        for pos in range(start,end):
            if source[pos] not in '\r\n': output[pos]=' '
    while index<len(source):
        start=index
        if source.startswith('//',index):
            end=source.find('\n',index);index=len(source) if end<0 else end;blank(start,index)
        elif source.startswith('/*',index):
            end=source.find('*/',index+2);index=len(source) if end<0 else end+2;blank(start,index)
        elif source[index] in '\"\'`':
            quote=source[index];index+=1
            while index<len(source):
                if source[index]=='\\': index+=2
                elif source[index]==quote: index+=1;break
                else: index+=1
            index=min(index,len(source))
            if strings: blank(start,index)
        elif source[index]=='/' and (not source[:index].rstrip() or source[:index].rstrip()[-1] in '=(:,[!&|?;{'):
            index+=1;character_class=False
            while index<len(source) and source[index]!='\n':
                char=source[index]
                if char=='\\': index+=2;continue
                if char=='[': character_class=True
                if char==']': character_class=False
                index+=1
                if char=='/' and not character_class: break
            if strings: blank(start,min(index,len(source)))
        else: index+=1
    return ''.join(output)


def javascript_findings(source):
    code=javascript_mask(source)
    imports=javascript_mask(source,strings=False)
    matches=[]
    for rule,pattern in [('JS001',r'\.innerHTML\s*=|\bdangerouslySetInnerHTML\s*='),
                         ('JS002',r'\beval\s*\(|\bnew\s+Function\s*\(')]:
        for match in re.finditer(pattern,code): matches.append((rule,source.count('\n',0,match.start())+1,'medium'))
    modules={'child_process'};functions=set()
    for match in re.finditer(r'''\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["'](?:node:)?child_process["']\s*\)''',imports): modules.add(match[1])
    for match in re.finditer(r'''import\s+\*\s+as\s+(\w+)\s+from\s*["'](?:node:)?child_process["']''',imports): modules.add(match[1])
    for match in re.finditer(r'''(?:\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*["'](?:node:)?child_process["']\s*\)|import\s*\{([^}]+)\}\s*from\s*["'](?:node:)?child_process["'])''',imports):
        for entry in (match[1] or match[2]).split(','):
            item=re.fullmatch(r'\s*(exec|execSync)(?:\s*(?::|as)\s*(\w+))?\s*',entry)
            if item: functions.add(item[2] or item[1])
    for match in re.finditer(r'\b(\w+)\s*\.\s*(exec|execSync)\s*\(|\b(\w+)\s*\(',code):
        if match[1] in modules or match[3] in functions:
            matches.append(('JS003',source.count('\n',0,match.start())+1,'medium'))
    return sorted(set(matches),key=lambda item:(item[1],item[0]))
