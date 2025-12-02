# SPDX-License-Identifier: Apache-2.0
"""Helpers to build Ansible playbooks for NetBox resources."""

from typing import Any, Dict, List, Optional

from jinja2 import Template
import yaml

from netbox_manager.config import settings

inventory = {
    "all": {
        "hosts": {
            "localhost": {
                "ansible_connection": "local",
                "ansible_python_interpreter": None,  # set by caller
            }
        }
    }
}

playbook_template = """
- name: Manage NetBox resources defined in {{ name }}
  connection: local
  hosts: localhost
  gather_facts: false

  vars:
    {{ vars | indent(4) }}

  tasks:
    {{ tasks | indent(4) }}
"""


def create_netbox_task(
    key: str,
    value: Dict[str, Any],
    register_var: Optional[str] = None,
    ignore_errors: bool = False,
) -> Dict[str, Any]:
    """Create a NetBox Ansible task from resource data."""
    state = value.pop("state", "present")

    update_vc_child = None
    if key == "device_interface" and "update_vc_child" in value:
        update_vc_child = value.pop("update_vc_child")

    task: Dict[str, Any] = {
        "name": f"Manage NetBox resource {value.get('name', '')} of type {key}".replace(
            "  ", " "
        ),
        f"netbox.netbox.netbox_{key}": {
            "data": value,
            "state": state,
            "netbox_token": str(settings.TOKEN),
            "netbox_url": settings.URL,
            "validate_certs": not settings.IGNORE_SSL_ERRORS,
        },
    }

    if update_vc_child is not None:
        netbox_module_key = f"netbox.netbox.netbox_{key}"
        netbox_module_config = task[netbox_module_key]
        assert isinstance(netbox_module_config, dict)
        netbox_module_config["update_vc_child"] = update_vc_child

    if register_var:
        task["register"] = register_var

    if ignore_errors:
        task["ignore_errors"] = True

    return task


def create_uri_task(
    value: Dict[str, Any],
    register_var: Optional[str] = None,
    ignore_errors: bool = False,
) -> Dict[str, Any]:
    """Create an ansible.builtin.uri task for direct NetBox API calls."""
    body = value.get("body", {})
    method = value.get("method", "GET")
    path = value.get("path", "")

    if path.startswith("/api/"):
        path = path[5:]
    elif path.startswith("api/"):
        path = path[4:]

    path = path.lstrip("/")

    netbox_url = settings.URL.rstrip("/")
    full_url = f"{netbox_url}/api/{path}"

    task: Dict[str, Any] = {
        "name": f"NetBox API call: {method} {path}",
        "ansible.builtin.uri": {
            "url": full_url,
            "method": method,
            "headers": {
                "Authorization": f"Token {str(settings.TOKEN)}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            "body_format": "json",
            "body": body if body else None,
            "validate_certs": not settings.IGNORE_SSL_ERRORS,
            "status_code": [200, 201, 204],
        },
    }

    if not body:
        uri_config = task["ansible.builtin.uri"]
        assert isinstance(uri_config, dict)
        del uri_config["body"]
        del uri_config["body_format"]

    if register_var:
        task["register"] = register_var

    if ignore_errors:
        task["ignore_errors"] = True

    return task


def create_ansible_playbook(
    file: str, template_vars: Dict[str, Any], template_tasks: List[Dict[str, Any]]
) -> str:
    """Create Ansible playbook from template variables and tasks."""
    template = Template(playbook_template)
    return template.render(
        {
            "name": file,
            "vars": yaml.dump(template_vars, indent=2, default_flow_style=False),
            "tasks": yaml.dump(template_tasks, indent=2, default_flow_style=False),
        }
    )

