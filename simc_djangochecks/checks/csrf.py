import ast
from pathblib import Path

from django.core.checks import register, Tags, Warning, Error
from django.core import settings

from simc_djangochecks import utils


class CsrfExemptVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

    def visit_FunctionDef(self, node):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "csrf_exempt":
                self.nodes.add(node)


@register(Tags.security)
def check_csrf_exempt(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("views.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = CsrfExemptVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning(f"{app.name} use csrf_exempt decorator")
                    )

    return errors


@register(Tags.security)
def check_csrf_middleware(**kwargs):
    if "django.middleware.csrf.CsrfViewMiddleware" not in settings.MIDDLEWARE:
        return [
            Error("CsrfViewMiddleware not found in MIDDLEWARE")
        ]
