import os

from setuptools import find_packages, setup

# Declare your non-python data files:
# Files underneath configuration/ will be copied into the build preserving the
# subdirectory structure if they exist.
data_files = []

setup(
    name="petunia",
    version="1.0",
    # declare your packages
    packages=find_packages(where="src", exclude=("test",)),
    package_dir={"": "src"},
    # include data files
    data_files=data_files,
    entry_points="""\
    [console_scripts]
    iptables-unroll = petunia.UnrollApp:main
    iptables-slice = petunia.SliceApp:main
    iptables-unslice = petunia.UnsliceApp:main
    iptables-scoreboard = petunia.ScoreboardApp:main
    tc-flower-load = petunia.LoadApp:main
    tc-flower-show = petunia.ShowApp:main
    """,

    # Enable build-time format checking
    check_format=False,

    # Enable type checking
    test_mypy=False,

    # Enable linting at build time
    test_flake8=False,

)
