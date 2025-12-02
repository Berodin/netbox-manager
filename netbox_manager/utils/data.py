# SPDX-License-Identifier: Apache-2.0
"""Data-centric helpers used across services."""

import os
from typing import Any, Dict, List


def get_leading_number(path: str) -> str:
    """Extract the leading number from a filename for grouping purposes."""
    basename = os.path.basename(path)
    return basename.split("-")[0]


def find_device_names_in_structure(data: Dict[str, Any]) -> List[str]:
    """Recursively search for device names in a nested data structure."""
    device_names: List[str] = []

    def _recursive_search(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "device" and isinstance(value, str):
                    device_names.append(value)
                elif isinstance(value, (dict, list)):
                    _recursive_search(value)
        elif isinstance(obj, list):
            for item in obj:
                _recursive_search(item)

    _recursive_search(data)
    return device_names


def should_skip_task_by_filter(key: str, task_filter: str) -> bool:
    """Check if task should be skipped based on task filter."""
    normalized_filter = task_filter.replace("-", "_")
    normalized_key = key.replace("-", "_")
    return normalized_key != normalized_filter


def extract_device_names_from_task(key: str, value: Dict[str, Any]) -> List[str]:
    """Extract all device names referenced in a task."""
    device_names = []

    if "device" in value:
        device_names.append(value["device"])
    elif key == "device" and "name" in value:
        device_names.append(value["name"])

    nested_device_names = find_device_names_in_structure(value)
    device_names.extend(nested_device_names)

    return device_names


def should_skip_task_by_device_filter(
    device_names: List[str], device_filters: List[str]
) -> bool:
    """Check if task should be skipped based on device filters."""
    if not device_names:
        return True

    return not any(
        filter_device in device_name
        for device_name in device_names
        for filter_device in device_filters
    )

