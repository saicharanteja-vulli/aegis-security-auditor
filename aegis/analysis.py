"""Bounded local syntax analysis, not whole-program taint analysis."""
import ast
from dataclasses import dataclass


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
    def visit_comprehension_scope(self,node):
        # Only the first iterable executes in this enclosing scope; the target
        # names must not become locals of the surrounding function.
        self.visit(node.generators[0].iter)
    visit_ListComp=visit_comprehension_scope
    visit_SetComp=visit_comprehension_scope
    visit_DictComp=visit_comprehension_scope
    visit_GeneratorExp=visit_comprehension_scope
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
        # Defaults are evaluated outside the lambda's parameter scope.
        for expression in [*node.args.defaults,*[v for v in node.args.kw_defaults if v]]:
            self.visit(expression)
        outer=self.env;self.env=dict(outer)
        parameters=[*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]
        if node.args.vararg: parameters.append(node.args.vararg)
        if node.args.kwarg: parameters.append(node.args.kwarg)
        for arg in parameters: self.env[arg.arg]=UNKNOWN
        self.visit(node.body);self.env=outer

    def visit_comprehension_expression(self,node):
        # Python evaluates the first iterable in the enclosing scope. Targets
        # belong to the separate comprehension scope and never leak outside.
        self.visit(node.generators[0].iter)
        outer=self.env;self.env=dict(outer)
        for generator in node.generators: self.assign(generator.target,UNKNOWN)
        for index,generator in enumerate(node.generators):
            if index: self.visit(generator.iter)
            for condition in generator.ifs: self.visit(condition)
        if isinstance(node,ast.DictComp):
            self.visit(node.key);self.visit(node.value)
        else: self.visit(node.elt)
        self.env=outer
    visit_ListComp=visit_comprehension_expression
    visit_SetComp=visit_comprehension_expression
    visit_DictComp=visit_comprehension_expression
    visit_GeneratorExp=visit_comprehension_expression

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
