import ast
from pathlib import Path

from django.core.checks import register, Tags, Error

from simc_djangochecks import utils


class PickleVisitor(ast.NodeVisitor):
    def __init__(self):
        self.found = False

    def visit_Import(self, node):
        for name in node.names:
            if name.name == "pickle":
                self.nodes.append(node)

    def visit_ImportFrom(self, node):
        if node.module == "pickle":
            self.nodes.append(node)


@register(Tags.security)
def check_pickle(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                node = ast.parse(fp.read())
                visitor = PickleVisitor()
                visitor.visit(node)
                for node in visitor.nodes:
                    errors.append(
                        Error(
                            "Il modulo pickle è sconsigliato",
                            hint="Usare un altro formato",
                            id="simc_djangochecks.E001",
                        )
                    )

    return errors


class XmlVisitor(ast.NodeVisitor):
    def __init__(self):
        self.found = False

    def visit_Import(self, node):
        for name in node.names:
            if name.name == "xml":
                self.found = True

    def visit_ImportFrom(self, node):
        if node.module == "xml":
            self.found = True


@register(Tags.security)
def check_xml(app_configs, **kwargs):
    errors = []

    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                node = ast.parse(fp.read())
                if XmlVisitor().visit(node).found:
                    errors.append(
                        Error(
                            "Il modulo xml è sconsigliato",
                            hint=(
                                "Usare un altro formato oppure la libreria "
                                "defusedxml"
                            ),
                            id="simc_djangochecks.E002",
                        )
                    )
