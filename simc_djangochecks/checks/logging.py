import re

from django.conf import settings
from django.core.checks import register, Tags, Warning, Error


@register(Tags.security)
def check_requestid_middleware(**kwargs):
    errors = []
    middleware = "log_request_id.middleware.RequestIDMiddleware"
    if middleware not in settings.MIDDLEWARES:
        errors.append(
            Error(
                f"{middleware} non presente in MIDDLEWARES",
                id="simc_djangochecks.E044",
            )
        )

    return errors


@register(Tags.security)
def check_logger(**kwargs):
    errors = []
    log = settings.LOGGING
    if not log["disable_existing_loggers"]:
        errors.append(
            Warning(
                "Loggers di default non disabilitati",
                id="simc_djangochecks.W045",
            )
        )

    has_syslog = False
    for h in log["loggers"][""]["handlers"]:
        handler = log["handlers"][h]
        if handler["class"] == "logging.handlers.SysLogHandler":
            has_syslog = True
            if not handler["facility"].startswith("local"):
                errors.append(
                    Warning(
                        (
                            "Syslog handler dovrebbe usare una delle facility "
                            "'local{0..7}'"
                        ),
                        id="simc_djangochecks.W046",
                    )
                )

            has_debug_false_filter = False
            has_request_id_filter = False
            for f in handler["filters"]:
                if log["filters"][f]["()"] == "django.utils.log.RequireDebugFalse":
                    has_debug_false_filter = True

                if log["filters"][f]["()"] == "request_id.logging.RequestIdFilter":
                    has_request_id_filter = True

            if not has_debug_false_filter:
                errors.append(
                    Warning(
                        (
                            "Syslog handler dovrebbe avere il "
                            "filtro RequireDebugFalse"
                        ),
                        id="simc_djangochecks.W047",
                    )
                )

            if not has_request_id_filter:
                errors.append(
                    Warning(
                        (
                            "Syslog handler dovrebbe avere il "
                            "filtro RequestIdFilter"
                        ),
                        id="simc_djangochecks.W048",
                    )
                )

            if not re.match(
                log["formatters"][h]["format"],
                r'^\w\[\{process\}]: \{name\} \{request_id\} \{message\}$'
            ):
                errors.append(
                    Warning(
                        "Il formato di syslog non è quello suggerito",
                        id="simc_djangochecks.W049",
                    )
                )

    if not has_syslog:
        errors.append(
            Warning(
                "Syslog logger mancante",
                id="simc_djangochecks.W050",
            )
        )

    return errors
