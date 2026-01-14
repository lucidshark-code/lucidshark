"""Configuration generation module.

This module provides generators for:
- lucidscan.yml configuration files
- Package manager tool installation
"""

from lucidscan.generation.config_generator import ConfigGenerator, InitChoices
from lucidscan.generation.package_installer import PackageInstaller

__all__ = [
    "ConfigGenerator",
    "InitChoices",
    "PackageInstaller",
]
