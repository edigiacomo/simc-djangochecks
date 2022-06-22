import os
from pathlib import Path
import re

from django.conf import settings
from django.core.checks import register, Tags, Error

from simc_django_checks import utils


def list_template_dirs(app_configs):
    dirs = []
    for template in settings.TEMPLATES:
        dirs += template['DIRS']

    for app in app_configs:
        dirs.append(os.path.join(app.path, "templates"))

    return dirs


@register(Tags.security)
def check_safe_tag(app_configs, **kwargs):
    errors = []
    for template_dir in list_template_dirs(utils.list_apps(app_configs)):
        for path in Path(template_dir).rglob("*.htm*"):
            with path.open() as fp:
                content = fp.read()
                if re.search(r'\{%\s*autoescape\s+on', content):
                    errors.append(
                        Error(
                            f"'autoscape on' in template {path}"
                        )
                    )

                if re.search(r'[|]\s*safe', content):
                    errors.append(
                        Error(
                            f"'safe' filter in template {path}"
                        )
                    )

                if re.search(r'[|]\s*safeseq', content):
                    errors.append(
                        Error(
                            f"'safeseq' filter in template {path}"
                        )
                    )

    return errors


@register(Tags.security)
def check_template_backend(app_configs, **kwargs):
    errors = []

    default_template = "django.template.backends.django.DjangoTemplates"
    for template in settings.TEMPLATES:
        if template["BACKEND"] != default_template:
            errors.append(
                Error(
                    f"Unknown template backend {template['BACKEND']}"
                )
            )

        try:
            if not template["OPTIONS"]["autoescape"]:
                errors.append(
                    Error(
                        "autoescape off in TEMPLATE"
                    )
                )
        except KeyError:
            pass

    return errors
