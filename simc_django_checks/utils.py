from django.apps import apps


def list_apps(app_configs):
    return app_configs if app_configs else [
        a for a in apps.get_app_configs()
        if not a.name.startswith("django.") and not a.name.startswith("simc_django_checks")
    ]
