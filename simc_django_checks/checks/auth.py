import re
import ast
from pathlib import Path

from django.core.checks import register, Tags, Warning, Error
from django.conf import settings
from django.utils.module_loading import import_string

from simc_django_checks import utils


@register(Tags.security)
def check_hashers(app_configs, **kwargs):
    errors = []
    default_hasher = settings.PASSWORD_HASHERS[0]
    weak_hasher_regex = re.compile('(sha1|md5|unsalted)', re.IGNORECASE)

    if weak_hasher_regex.search(default_hasher):
        errors.append(
            Error(f"Weak default hasher: {default_hasher}")
        )

    for hasher in settings.PASSWORD_HASHERS[1:]:
        if weak_hasher_regex.search(hasher):
            errors.append(
                Warning(f"Weak hasher: {hasher}")
            )

    for hasher in settings.PASSWORD_HASHERS:
        try:
            hasher_cls = import_string(hasher)
            salt = hasher_cls().salt()
            if not salt:
                errors.append(
                    Error(f"Unsalted hasher: {hasher}")
                )
        except ValueError:
            pass

    return errors


class MakePasswordVisitor(ast.NodeVisitor):
    nodes = []

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "make_password"
        ):
            if len(node.args) > 1:
                self.nodes.append(node)
            else:
                for k in node.keywords:
                    if k.arg in ("salt", "hasher"):
                        self.nodes.append(node)
                        break


@register(Tags.security)
def check_make_password(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = MakePasswordVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning((
                            f"{app.name} use make_password "
                            "with explicit salt or hasher"
                        ))
                    )

    return errors


@register(Tags.security)
def check_password_validators(app_configs, **kwargs):
    errors = []
    if len(settings.AUTH_PASSWORD_VALIDATORS) == 0:
        errors.append(
            Error("Empty AUTH_PASSWORD_VALIDATORS")
        )

    suggested_validators = (
        "django.contrib.auth.password_validation.MinimumLengthValidator",
        (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
        "django.contrib.auth.password_validation.CommonPasswordValidator",
        (
            "django_password_validators.password_character_requirements."
            "password_validation.PasswordCharacterValidator"
        ),
    )
    for validator in suggested_validators:
        if validator not in (
            o["NAME"] for o in settings.AUTH_PASSWORD_VALIDATORS
        ):
            errors.append(
                Warning(
                    f"Missing {validator} in AUTH_PASSWORD_VALIDATORS"
                )
            )

    return errors


class AuthenticateVisitor(ast.NodeVisitor):
    nodes = []

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "authenticate"
        ):
            self.nodes.append(node)


@register(Tags.security)
def check_authenticate(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("*.py"):
            with path.open() as fp:
                module = ast.parse(fp.read())
                visitor = AuthenticateVisitor()
                visitor.visit(module)
                for node in visitor.nodes:
                    errors.append(
                        Warning((
                            f"{app.name} use authenticate method "
                        ))
                    )

    return errors


@register(Tags.security)
def check_authentication_backends(app_configs, **kwargs):
    errors = []

    allowed_backends = [
        "django.contrib.auth.backends.ModelBackend",
        "django_auth_ldap.backend.LDAPBackend",
    ]

    for backend in settings.AUTHENTICATION_BACKENDS:
        if backend not in allowed_backends:
            errors.append(Error((
                "AUTHENTICATION_BACKENDS: unknown authentication "
                f"backend {backend}"
            )))

    return errors
