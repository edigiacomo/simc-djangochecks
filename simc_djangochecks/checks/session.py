import tempfile
from pathlib import Path

from django.core.checks import register, Tags, Warning, Error
from django.conf import settings


@register(Tags.security)
def check_session_is_installed(app_configs, **kwargs):
    errors = []
    session_middleware = "django.contrib.sessions.middleware.SessionMiddleware"
    if session_middleware not in settings.MIDDLEWARE:
        errors.append(
            Error(
                f"{session_middleware} non presente in MIDDLEWARE",
                id="simc_djangochecks.E028",
            )
        )

    return errors


@register(Tags.security)
def check_session_serializer(app_configs, **kwargs):
    errors = []
    suggested_serializer = "django.contrib.sessions.serializers.JSONSerializer"
    pickle_serializer = "django.contrib.sessions.serializers.PickleSerializer"
    if settings.SESSION_SERIALIZER == pickle_serializer:
        errors.append(
            Error(
                f"Uso di {pickle_serializer} in SESSION_SERIALIZER",
                hint="Usa {suggested_serializer}",
                id="simc_djangochecks.E029",
            )
        )
    elif settings.SESSION_SERIALIZER != suggested_serializer:
        errors.append(
            Warning(
                f"SESSION_SERIALIZER diverso da {suggested_serializer}",
                id="simc_djangochecks.W030",
            )
        )

    return errors


@register(Tags.security)
def check_session_type(app_configs, **kwargs):
    errors = []
    if settings.SESSION_ENGINE == "django.contrib.sessions.backends.db":
        if "django.contrib.sessions" not in settings.INSTALLED_APPS:
            errors.append(
                Error(
                    (

                        "SESSION_ENGINE django.contrib.sessions.backends.db "
                        "richiede django.contrib.sessions in INSTALLED_APPS"
                    ),
                    id="simc_djangochecks.E031",
                )
            )
    elif (
        settings.SESSION_ENGINE == "django.contrib.sessions.backends.file"
    ):
        if settings.SESSION_FILE_PATH == tempfile.gettempdir():
            errors.append(
                Error(
                    (
                        "SESSION_ENGINE django.contrib.sessions.backends.file "
                        "richiede un SESSION_FILE_PATH che non sia la "
                        "directory temporanea"
                    ),
                    id="simc_djangochecks.E032",
                )
            )
        else:
            cache_path = Path(settings.SESSION_FILE_PATH)
            for name, path in (
                ("MEDIA_ROOT", settings.MEDIA_ROOT),
                ("STATIC_ROOT", settings.STATIC_ROOT),
                ("/var/www/html", "/var/www/html"),
            ):
                path = Path(path)
                if cache_path == path or path in cache_path:
                    errors.append(
                        Error(
                            f"SESSION_FILE_PATH uguale o contenuto in {path}",
                            id="simc_djangochecks.E033",
                        )
                    )
    elif (
        settings.SESSION_ENGINE in (
            "django.contrib.sessions.backends.cache",
            "django.contrib.sessions.backends.cached_db",
        )
    ):
        cache = settings.CACHES[settings.SESSION_CACHE_ALIAS]["BACKEND"]
        if cache != "django_redis.cache.RedisCache":
            errors.append(
                Error(
                    "Session su cache deve usare Redis come backend",
                    id="simc_djangochecks.E034"
                )
            )
    elif settings.SESSION_ENGINE == ("django.contrib.sessions."
                                     "backends.signed_cookies"):
        errors.append(
            Error(
                (
                    "Invalid SESSION_ENGINE django.contrib.sessions."
                    "backends.signed_cookies"
                ),
                id="simc_djangochecks.E035",
            )
        )
    else:
        errors.append(
            Warning(
                f"SESSION_ENGINE sconosciuto: {settings.SESSION_ENGINE}",
                id="simc_djangochecks.W036",
            )
        )

    return errors


@register(Tags.security)
def check_session_cookie_attributes(**kwargs):
    errors = []

    if not settings.SESSION_COOKIE_HTTPONLY:
        errors.append(
            Error(
                "SESSION_COOKIE_HTTPONLY deve essere True",
                id="simc_djangochecks.E037",
            )
        )

    if settings.SESSION_COOKIE_SAMESITE not in ("Strict", "Lax"):
        errors.append(
            Error(
                "SESSION_COOKIE_SAMESITE deve essere Strict or Lax",
                id="simc_djangochecks.E038",
            )
        )

    if not settings.SESSION_COOKIE_SECURE:
        errors.append(
            Error(
                "SESSION_COOKIE_SECURE deve essere True",
                id="simc_djangochecks.E039",
            )
        )

    if not settings.SESSION_EXPIRE_AT_BROWSER_CLOSE:
        errors.append(
            Error(
                "SESSION_EXPIRE_AT_BROWSER_CLOSE deve essere True",
                id="simc_djangochecks.E040",
            )
        )

    if settings.SESSION_COOKIE_AGE > (8 * 3600):
        errors.append(
            Warning(
                "SESSION_COOKIE_AGE maggiore di 8h",
                id="simc_djangochecks.W041",
            )
        )

    return errors
