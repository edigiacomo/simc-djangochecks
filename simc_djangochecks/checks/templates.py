import os
from pathlib import Path
import re

from django.conf import settings
from django.core.checks import register, Tags, Error, Warning

from simc_djangochecks import utils


def list_template_dirs(app_configs):
    dirs = []
    for template in settings.TEMPLATES:
        dirs += template["DIRS"]

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
                if re.search(r"\{%\s*autoescape\s+on", content):
                    errors.append(
                        Error(
                            f"Uso di 'autoscape on' nel template {path}",
                            id="simc_djangochecks.E015",
                        )
                    )

                if re.search(r"[|]\s*safe", content):
                    errors.append(
                        Warning(
                            f"Uso del 'safe' filter nel template {path}",
                            id="simc_djangochecks.E016",
                        )
                    )

                if re.search(r"[|]\s*safeseq", content):
                    errors.append(
                        Warning(
                            f"Uso di 'safeseq' filter in template {path}",
                            id="simc_djangochecks.E017",
                        )
                    )

    return errors


@register(Tags.security)
def check_template_backend(app_configs, **kwargs):
    errors = []

    default_template = "django.template.backends.django.DjangoTemplates"
    for template in settings.TEMPLATES:
        backend = template["BACKEND"]
        if backend != default_template:
            errors.append(
                Warning(
                    f"Uso di template {backend} invece di {default_template}",
                    id="simc_djangochecks.W018",
                )
            )

        try:
            if not template["OPTIONS"]["autoescape"]:
                errors.append(
                    Error(
                        "autoescape off in TEMPLATE",
                        id="simc_djangochecks.E019",
                    )
                )
        except KeyError:
            pass

    return errors
