# SPDX-License-Identifier: Apache-2.0
"""NetBox API adapter helpers."""

from typing import Any, Optional

import pynetbox

from netbox_manager.config import settings


def create_netbox_api(custom_url: Optional[str] = None, custom_token: Optional[str] = None) -> pynetbox.api:
    """Create and configure NetBox API connection."""
    url = custom_url or settings.URL
    token = str(custom_token or settings.TOKEN)
    api = pynetbox.api(url, token=token)
    if settings.IGNORE_SSL_ERRORS:
        api.http_session.verify = False
    return api


def get_device_role_slug(device: Any) -> str:
    """Extract device role slug from a device object."""
    if not device.role:
        return ""

    if hasattr(device.role, "slug"):
        return device.role.slug.lower()
    if hasattr(device.role, "name"):
        return device.role.name.lower()
    return ""


def get_resource_name(resource: Any) -> str:
    """Extract a displayable name from a resource object."""
    return getattr(
        resource,
        "name",
        getattr(
            resource,
            "address",
            getattr(resource, "id", "unknown"),
        ),
    )

