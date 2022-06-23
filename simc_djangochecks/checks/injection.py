import ast
from pathlib import Path

from django.core.checks import register, Tags, Error

from simc_djangochecks import utils


class ForbiddenCallVisitor(ast.NodeVisitor):
    def __init__(self, name):
        self.nodes = []
        self.name = name

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == self.name
        ):
            self.nodes.append(node)


class RawSQLVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "RawSQL"
        ):
            self.nodes.append(node)

    def visit_Attribute(self, node):
        if node.attr == "RawSQL":
            self.nodes.append(node)


class ExtraVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

    def visit_keyword(self, node):
        if node.arg in ("extra", "extra_content"):
            self.nodes.append(node)


@register(Tags.security)
def check_exec(app_configs, **kwargs):
    errors = []

    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                for call in ("exec", "eval"):
                    visitor = ForbiddenCallVisitor(call)
                    visitor.visit(module)
                    for node in visitor.nodes:
                        errors.append(
                            Error(f"{app.name} use {call}")
                        )

    return errors


@register(Tags.security)
def check_sqlinjection(app_configs, **kwargs):
    errors = []

    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())

                visitor = RawSQLVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Error(f"{app.name} use RawSQL")
                    )

                visitor = ExtraVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning(f"{app.name} use extra or extra_content")
                    )

    return errors
