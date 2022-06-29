import json

from django.core.checks import register, Tags, Warning
from django.db.models import (
    BinaryField,
    CharField,
    IntegerField,
    FloatField,
    JSONField,
    TextField,
    FileField,
    ImageField,
)
from django.core.validators import MinValueValidator, MaxValueValidator

from simc_djangochecks import utils


def check_model_fields(model):
    errors = []
    for field in model._meta.get_fields():
        if isinstance(field, BinaryField):
            errors.append(
                Warning(
                    f"Il file '{field.name}' è un BinaryField",
                    obj=model,
                    hint="Usa un FileField o un ImageField",
                    id="simc_djangochecks.W003",
                )
            )

        for cls in (CharField, TextField):
            if (
                type(field) == cls
                and len(field.validators) < 2
                and not field.choices
            ):
                errors.append(
                    Warning(
                        f"{cls.__name__} '{field.name}' senza validatori",
                        obj=model,
                        id="simc_djangochecks.W004",
                    )
                )

        for cls in (FloatField, IntegerField):
            if type(field) == cls and not field.choices:
                for validator in (MinValueValidator, MaxValueValidator):
                    if validator not in field.validators:
                        errors.append(
                            Warning(
                                (
                                    f"{cls.__name__} '{field.name}' "
                                    f"senza validatore {validator.__name__}"
                                ),
                                obj=model,
                                id="simc_djangochecks.W005",
                            )
                        )

        for cls in (FileField, ImageField):
            if type(field) == cls and not field.validators:
                errors.append(
                    Warning(
                        f"{cls.__name__} '{field.name}' senza validatori",
                        obj=model,
                        id="simc_djangochecks.W006",
                    )
                )

        if type(field) == JSONField:
            if not isinstance(field.encoder, json.JSONEncoder):
                errors.append(
                    Warning(
                        f"Field {field.name} con un encoder custom",
                        obj=model,
                        id="simc_djangochecks.W007",
                    )
                )

            if not isinstance(field.decoder, json.JSONDecoder):
                errors.append(
                    Warning(
                        f"Field {field.name} con un decoder custom",
                        obj=model,
                        id="simc_djangochecks.W008",
                    )
                )

    return errors


@register(Tags.security)
def check_models_fields(app_configs, **kwargs):
    errors = []
    for app in utils.list_apps(app_configs):
        models = app.get_models()
        for model in models:
            errors += check_model_fields(model)

    return errors
