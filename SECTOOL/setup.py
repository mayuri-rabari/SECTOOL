from setuptools import setup, find_packages

setup(
    name="sectool",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "sectool=sectool:main",
        ]
    },
)
