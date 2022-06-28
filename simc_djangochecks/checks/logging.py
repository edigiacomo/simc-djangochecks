import re

from django.conf import settings
from django.core.checks import register, Tags, Warning, Error


@register(Tags.security)
def check_requestid_middleware(**kwargs):
    errors = []
    middleware = "log_request_id.middleware.RequestIDMiddleware"
    if middleware not in settings.MIDDLEWARES:
        errors.append(
            Error(f"Missing {middleware} from MIDDLEWARES")
        )

    return errors


@register(Tags.security)
def check_logger(**kwargs):
    errors = []
    log = settings.LOGGING
    if not log["disable_existing_loggers"]:
        errors.append(
            Warning("Existing loggers not disabled")
        )

    has_syslog = False
    for h in log["loggers"][""]["handlers"]:
        handler = log["handlers"][h]
        if handler["class"] == "logging.handlers.SysLogHandler":
            has_syslog = True
            if not handler["facility"].startswith("local"):
                errors.append(
                    Warning(
                        "Syslog handler should use facility 'local{0..7}'"
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
                        "syslog should have RequireDebugFalse filter"
                    )
                )

            if not has_request_id_filter:
                errors.append(
                    Warning(
                        "syslog should have RequestIdFilter filter"
                    )
                )

            if not re.match(
                log["formatters"][h]["format"],
                r'^\w\[\{process\}]: \{name\} \{request_id\} \{message\}$'
            ):
                errors.append(
                    Warning(
                        "wrong syslog format"
                    )
                )

    if not has_syslog:
        errors.append(
            Error(
                "Missing syslog logger"
            )
        )

    return errors
