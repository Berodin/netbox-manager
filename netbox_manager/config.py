# SPDX-License-Identifier: Apache-2.0
"""Configuration and application-wide settings."""

from dynaconf import Dynaconf, ValidationError, Validator
from loguru import logger
import typer

# Shared application settings loaded from files or environment
settings = Dynaconf(
    envvar_prefix="NETBOX_MANAGER",
    settings_files=["settings.toml", ".secrets.toml"],
    load_dotenv=True,
)

# Register base validators
settings.validators.register(
    Validator("DEVICETYPE_LIBRARY", is_type_of=str)
    | Validator("DEVICETYPE_LIBRARY", is_type_of=None, default=None),
    Validator("MODULETYPE_LIBRARY", is_type_of=str)
    | Validator("MODULETYPE_LIBRARY", is_type_of=None, default=None),
    Validator("RESOURCES", is_type_of=str)
    | Validator("RESOURCES", is_type_of=None, default=None),
    Validator("VARS", is_type_of=str)
    | Validator("VARS", is_type_of=None, default=None),
    Validator("IGNORED_FILES", is_type_of=list)
    | Validator(
        "IGNORED_FILES",
        is_type_of=None,
        default=["000-external.yml", "000-external.yaml"],
    ),
    Validator("IGNORE_SSL_ERRORS", is_type_of=bool)
    | Validator(
        "IGNORE_SSL_ERRORS",
        is_type_of=str,
        cast=lambda v: v.lower() in ["true", "yes"],
        default=False,
    ),
    Validator("VERBOSE", is_type_of=bool)
    | Validator(
        "VERBOSE",
        is_type_of=str,
        cast=lambda v: v.lower() in ["true", "yes"],
        default=False,
    ),
)

# Device role constants
NETBOX_NODE_ROLES = [
    "compute",
    "storage",
    "resource",
    "control",
    "manager",
    "network",
    "metalbox",
    "dpu",
    "loadbalancer",
    "router",
    "firewall",
]

NETBOX_SWITCH_ROLES = [
    "accessleaf",
    "borderleaf",
    "computeleaf",
    "dataleaf",
    "leaf",
    "serviceleaf",
    "spine",
    "storageleaf",
    "superspine",
    "switch",
    "transferleaf",
]


def validate_netbox_connection() -> None:
    """Validate NetBox connection settings."""
    settings.validators.register(
        Validator("TOKEN", is_type_of=(str, int)),
        Validator("URL", is_type_of=str),
    )
    try:
        settings.validators.validate_all()
    except ValidationError as exc:
        logger.error(f"Error validating NetBox connection settings: {exc.details}")
        raise typer.Exit()

