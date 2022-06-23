import tempfile

from django.core.checks import register, Tags, Warning, Error
from django.conf import settings


@register(Tags.security)
def check_session_is_installed(app_configs, **kwargs):
    errors = []
    session_middleware = "django.contrib.sessions.middleware.SessionMiddleware"
    if session_middleware not in settings.MIDDLEWARE:
        errors.append(
            Error(f"Missing {session_middleware} from MIDDLEWARE")
        )

    return errors


@register(Tags.security)
def check_session_serializer(app_configs, **kwargs):
    errors = []
    session_serializer = "django.contrib.sessions.serializers.JSONSerializer"
    if settings.SESSION_SERIALIZER != session_serializer:
        errors.append(
            Warning(f"SESSION_SERIALIZER should be {session_serializer}")
        )

    return errors


@register(Tags.security)
def check_session_type(app_configs, **kwargs):
    errors = []
    if (
        settings.SESSION_ENGINE == "django.contrib.sessions.backends.db"
        and "django.contrib.sessions" not in settings.INSTALLED_APPS
    ):
        errors.append(
            Error((
                "SESSION_ENGINE django.contrib.sessions.backends.db "
                "requires django.contrib.sessions in INSTALLED_APPS"
            ))
        )
    elif (
        settings.SESSION_ENGINE == "django.contrib.sessions.backends.file"
        and settings.SESSION_FILE_PATH == tempfile.gettempdir()
    ):
        errors.append(
            Error((
                "SESSION_ENGINE django.contrib.sessions.backends.file "
                "requires a SESSION_FILE_PATH != {tempfile.gettempdir()}"
            ))
        )
    elif settings.SESSION_ENGINE == ("django.contrib.sessions."
                                     "backends.signed_cookies"):
        errors.append(
            Error((
                "Invalid SESSION_ENGINE django.contrib.sessions."
                "backends.signed_cookies"))
        )
    else:
        errors.append(
            Warning(
                f"Unknonw SESSION_ENGINE {settings.SESSION_ENGINE}"
            )
        )

    return errors
