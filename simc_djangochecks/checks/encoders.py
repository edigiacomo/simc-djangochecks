import ast
from pathlib import Path

from django.core.checks import register, Tags, Warning

from simc_djangochecks import utils


class MarkSafeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == "mark_safe":
            self.nodes.append(node)


@register(Tags.security)
def check_mark_safe(app_configs, **kwargs):
    errors = []

    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = MarkSafeVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning(
                            f"{app.name} usa mark_safe",
                            id="simc_djangochecks.W020",
                        )
                    )

    return errors
