from setuptools import setup, find_packages


setup(
    name="simc_djangochecks",
    version="0.1",
    packages=find_packages(include=[
        "simc_djangochecks",
        "simc_djangochecks.*",
        "simc_djangochecks.checks.*",
    ]),
)
