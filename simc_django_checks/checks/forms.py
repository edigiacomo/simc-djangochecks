import inspect
import importlib
from pathlib import Path
import json

from django.core.checks import register, Tags, Info, Warning
from django.forms import (
    CharField, IntegerField, FloatField, JSONField,
    FileField,
)

from simc_django_checks import utils


def check_charfield_form(form_name, form_obj, field_name, field_obj):
    errors = []
    if isinstance(field_obj, CharField):
        if len(field_obj.validators) < 2:
            errors.append(
                Info(
                    f"Field '{field_name}' without validators",
                    obj=form_name,
                )
            )

    return errors


def check_numberfield_form(form_name, form_obj, field_name, field_obj):
    errors = []
    if any((
        isinstance(field_obj, model)
        for model in (
            FloatField, IntegerField
        )
    )):
        if not hasattr(field_obj, "min_value"):
            errors.append(
                Info(
                    f"Field '{field_name}' without min_value",
                    obj=form_name,
                )
            )
            if not hasattr(field_obj, "max_value"):
                errors.append(
                    Info(
                        f"Field '{field_name}' without min_value",
                        obj=form_name,
                    )
                )
    return errors


def check_jsonfield_form(form_name, form_obj, field_name, field_obj):
    errors = []
    if isinstance(field_obj, JSONField):
        if not isinstance(field_obj.encoder, json.JSONEncoder):
            errors.append(
                Warning(
                    f"Field {field_name} with a custom encoder",
                    obj=form_name,
                )
            )

        if not isinstance(field_obj.decoder, json.JSONDecoder):
            errors.append(
                Warning(
                    f"Field {field_name} with a custom decoder",
                    obj=form_name,
                )
            )

        if len(field_obj.validators) < 1:
            errors.append(
                Warning(
                    f"Field {field_name} without validators",
                    obj=form_name,
                )
            )

    return errors


def check_filefield_form(form_name, form_obj, field_name, field_obj):
    errors = []
    if isinstance(field_obj, FileField):
        if not field_obj.validators:
            errors.append(
                Warning(
                    f"Field {field_name} without validators",
                    obj=form_name,
                )
            )

    return errors


def check_form_fields(form_name, form_obj):
    errors = []
    for field_name, field_obj in form_obj.declared_fields.items():
        for check in (
            check_charfield_form,
            check_numberfield_form,
            check_jsonfield_form,
            check_filefield_form,
        ):
            errors += check(
                form_name, form_obj,
                field_name, field_obj,
            )

    return errors


@register(Tags.security)
def check_forms_fields(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        for path in Path(app.path).rglob("forms.py"):
            spec = importlib.util.spec_from_file_location("forms", path)
            module = spec.loader.load_module()
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and hasattr(obj, "declared_fields"):
                    errors += check_form_fields(name, obj)
    return errors
