from setuptools import setup, find_packages


setup(
    name="simc-djangochecks",
    version="0.1",
    packages=find_packages(include=[
        "simc_django_checks",
        "simc_django_checks.*",
        "simc_django_checks.checks.*",
    ]),
)
