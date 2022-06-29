import os
import sys
import ast
from pathlib import Path

from django.core.checks import register, Tags, Warning, Error
from django.conf import settings

from simc_djangochecks import utils


class AssignSettingVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nodes = []

    def visit_Assign(self, node):
        for target in node.targets:
            # django.conf.settings.NAME = VALUE
            if (
                isinstance(target.value, ast.Attribute)
                and isinstance(target.value.value, ast.Attribute)
                and isinstance(target.value.value.value, ast.Name)
                and target.value.value.value.id == "django"
                and target.value.value.value.attr == "conf"
                and target.value.attr == "settings"
            ):
                self.nodes.append(node)
                continue

            # conf.settings.NAME = VALUE
            if (
                isinstance(target.value, ast.Attribute)
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id == "conf"
                and target.value.value.attr == "settings"
            ):
                self.nodes.append(node)
                continue

            # settings.NAME = VALUE
            if (
                isinstance(target.value, ast.Name)
                and target.value.id == "settings"
            ):
                self.nodes.append(node)
                continue


@register(Tags.security)
def check_settings_modification(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            if "settings" in path:
                continue

            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = AssignSettingVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning(
                            "Assign settings outside of settings.py"
                        )
                    )

    return errors


def get_settings_module_ast():
    settings_module = os.env["DJANGO_SETTINGS_MODULE"]
    settings_path = Path(sys.modules[settings_module].__file__)
    with settings_path.open() as fp:
        return ast.parse(fp.read())


def is_assign_variable(node, varname):
    for target in node.targets:
        if target.id == varname:
            return True


class SecretKeyVisitor(ast.NodeVisitor):
    def __init__(self):
        self.errors = []

    def visit_Assign(self, node):
        if (
            is_assign_variable("SECRET_KEY")
            and isinstance(node.value, ast.Constant)
        ):
            self.errors.append(
                Error("Hardcoded SECRET_KEY")
            )


@register(Tags.security)
def check_secret_key(**kwargs):
    module = get_settings_module_ast()
    return SecretKeyVisitor().visit(module).errors


@register(Tags.security)
def check_allowed_hosts(**kwarg):
    if "*" in settings.ALLOWED_HOSTS:
        return [
            Error("ALLOWED_HOSTS contains wildcard '*'")
        ]
