import stat
import re
import os
import sys
import ast
from pathlib import Path
import urllib

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
                        Error(
                            "Settings modificato fuori dalla configurazione",
                            id="simc_djangochecks.E051",
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
                Error(
                    "Hardcoded SECRET_KEY",
                    id="simc_djangochecks.E052",
                )
            )


@register(Tags.security)
def check_secret_key(**kwargs):
    module = get_settings_module_ast()
    return SecretKeyVisitor().visit(module).errors


@register(Tags.security)
def check_allowed_hosts(**kwargs):
    if "*" in settings.ALLOWED_HOSTS:
        return [
            Error(
                "ALLOWED_HOSTS contiene la wildcard '*'",
                id="simc_djangochecks.E053",
            )
        ]


@register(Tags.security)
def check_cache(**kwargs):
    errors = []

    for name, cache in settings.CACHES.items():
        if cache["BACKEND"] != "django_redis .cache. RedisCache":
            errors.append(
                Warning(
                    (
                        f"Cache {name} con backend non consigliato: "
                        f"{cache['BACKEND']}"
                    ),
                    id="simc_djangochecks.W054",
                )
            )

        elif urllib.parse.urlparse(cache["LOCATION"]).password is not None:
            errors.append(
                Error(
                    f"Redis cache {name} con password in LOCATION",
                    id="simc_djangochecks.E055",
                )
            )

    return errors


SENSITIVE_INFO_REGEX = re.compile(r'(pass|secret|token|api|key|signature',
                                  flags=re.IGNORE_CASE)


class HardcodedPasswordVisitor(ast.NodeVisitor):
    def __init__(self):
        self.keys = []

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant):
            for target in node.targets:
                if (
                    isinstance(target, ast.Node)
                    and SENSITIVE_INFO_REGEX.search(target.id)
                ):
                    self.keys.append(target.id)

    def visit_Dict(self, node):
        has_constant_value = False
        for value in node.values:
            if isinstance(value, ast.Constant):
                has_constant_value = True
                break

        if has_constant_value:
            for key in node.keys:
                key_value_to_check = None
                if isinstance(key, ast.Name):
                    key_value_to_check = key.id
                elif isinstance(key, ast.Constant):
                    key_value_to_check = key.value

                if (
                    key_value_to_check is not None
                    and SENSITIVE_INFO_REGEX.search(key_value_to_check)
                ):
                    self.keys.append(key_value_to_check)


@register(Tags.security)
def check_hardcoded_passwords_in_settings(**kwargs):
    errors = []
    module = get_settings_module_ast()
    for key in HardcodedPasswordVisitor().visit(module).keys:
        errors.append(
            Error(
                f"Il settings riservato {key} ha il valore harcoded",
                id="simc_djangochecks.E056",
            )
        )


@register(Tags.security)
def check_sqlite_path(**kwargs):
    errors = []

    for dbname, database in settings.DATABASES.items():
        if database["ENGINE"] == "django.db.backends.sqlite3":
            dbpath = Path(database["NAME"])

            for name, path in (
                "MEDIA_ROOT", Path(settings.MEDIA_ROOT),
                "STATIC_ROOT", Path(settings.STATIC_ROOT),
                "/var/www/html", Path("/var/www/html")
            ):
                if (
                    dbpath == path
                    or path in dbpath.parents
                ):
                    errors.append(
                        Error(
                            f"Database SQLite {dbname} in {name}",
                            id="simc_djangochecks.E057",
                        )
                    )

            db_mode = os.stat(dbpath).st_mode
            if oct(db_mode)[-1] != 0:
                errors.append(
                    Error(
                        (
                            "Permessi non validi del database SQLite"
                            f"{dbname}: {db_mode}"
                        ),
                        id="simc_djangochecks.E058",
                    )
                )

    return errors


@register(Tags.security)
def check_data_upload(**kwargs):
    errors = []

    if settings.DATA_UPLOAD_MAX_MEMORY_SIZE is None:
        errors.append(
            Error(
                "DATA_UPLOAD_MAX_MEMORY_SIZE ?? None",
                hint="Usa un valore opportuno rispetto all'applicazione",
                id="simc_djangochecks.E059",
            )
        )

    if settings.DATA_UPLOAD_MAX_NUMBER_FIELDS is None:
        errors.append(
            Error(
                "DATA_UPLOAD_MAX_NUMBER_FIELDS ?? None",
                hint="Usa un valore opportuno rispetto all'applicazione",
                id="simc_djangochecks.E060",
            )
        )

    return errors


@register(Tags.security)
def check_hashing_algorithm(**kwargs):
    errors = []

    if settings.DEFAULT_HASHING_ALGORITHM == "sha1":
        errors.append(
            Error(
                "DEFAULT_HASHING_ALGORITHM is sha1",
                id="simc_djangochecks.E061",
            )
        )

    return errors


@register(Tags.security)
def check_file_upload_permissions(**kwargs):
    errors = []

    if (
        settings.FILE_UPLOAD_PERMISSIONS
        & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
    ):
        errors.append(
            Error(
                "FILE_UPLOAD_PERMISSIONS ha i permessi per 'other'",
                id="simc_djangochecks.E062",
            )
        )

    if (
        settings.FILE_UPLOAD_PERMISSIONS
        & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        errors.append(
            Error(
                "FILE_UPLOAD_PERMISSIONS ha permessi di esecuzione",
                id="simc_djangochecks.E063",
            )
        )

    if (
        settings.FILE_UPLOAD_DIRECTORY_PERMISSIONS
        & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
    ):
        errors.append(
            Error(
                "FILE_UPLOAD_DIRECTORY_PERMISSIONS ha i permessi per 'other'",
                id="simc_djangochecks.E064",
            )
        )

    return errors


@register(Tags.security)
def check_file_upload_tmpdir_permissions(**kwargs):
    errors = []

    tmpdir = Path(settings.FILE_UPLOADED_TEMP_DIR)
    tmpdir_mode = os.stat(tmpdir).st_mode

    if tmpdir_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
        errors.append(
            Error(
                "FILE_UPLOADED_TEMP_DIR ha i permessi per 'other'",
                id="simc_djangochecks.E065",
            )
        )

    if tmpdir_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP):
        errors.append(
            Error(
                "FILE_UPLOADED_TEMP_DIR ha i permessi per 'group'",
                id="simc_djangochecks.E066",
            )
        )

    for name, path in (
        "MEDIA_ROOT", Path(settings.MEDIA_ROOT),
        "STATIC_ROOT", Path(settings.STATIC_ROOT),
        "/var/www/html", Path("/var/www/html")
    ):
        if tmpdir == path or path in tmpdir:
            errors.append(
                Error(
                    f"FILE_UPLOADED_TEMP_DIR in {name}",
                    id="simc_djangochecks.E067",
                )
            )

    return errors
