import ast
from pathlib import Path

from django.core.checks import register, Tags, Warning, Error

from simc_djangochecks import utils


class PickleVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

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
                        Error("Detected pickle usage")
                    )

    return errors
