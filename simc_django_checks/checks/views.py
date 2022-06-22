import ast
import inspect
import importlib
from pathlib import Path
import json

from django.core.checks import register, Tags, Info, Warning
from django.apps import apps

from simc_django_checks import utils


class ReturnHttpResponseVisitor(ast.NodeVisitor):
    nodes = []

    def visit_Return(self, node):
        if (
            isinstance(node.value, ast.Call)
            and ((
                isinstance(node.value.func, ast.Name)
                and node.value.func.id == "HttpResponse"
            ) or (
                isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "HttpResponse"
            ))
        ):
            is_html = False
            if node.value.keywords:
                for keyword in node.value.keywords:
                    if (
                        keyword.arg == "content_type"
                        and isinstance(keyword.value, ast.Constant)
                        and "html" in keyword.value.value
                    ):
                        is_html = True
                        break
            else:
                is_html = True

            if is_html:
                self.nodes.append(node)


@register(Tags.security)
def check_response(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("views.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = ReturnHttpResponseVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning(
                            f"View in app {app.name} return html HttpResponse"
                        )
                    )

    return errors
