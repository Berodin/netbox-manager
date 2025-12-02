# SPDX-License-Identifier: Apache-2.0
"""YAML helpers and utilities."""

from copy import deepcopy
import glob
import os
from typing import Any, Dict, List

from loguru import logger
import yaml

from netbox_manager.config import settings


class ProperIndentDumper(yaml.Dumper):
    """Custom YAML Dumper that properly indents nested sequences."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        """Override to prevent indentless sequences."""
        return super(ProperIndentDumper, self).increase_indent(flow, False)


def deep_merge(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries, with dict2 values taking precedence."""
    result = deepcopy(dict1)

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)

    return result


def find_yaml_files(directory: str) -> List[str]:
    """Find all YAML files in a directory and return sorted list."""
    yaml_files = []
    for ext in ["*.yml", "*.yaml"]:
        yaml_files.extend(glob.glob(os.path.join(directory, ext)))
    return sorted(yaml_files)


def load_global_vars() -> Dict[str, Any]:
    """Load and merge global variables from the VARS directory."""
    global_vars: Dict[str, Any] = {}

    vars_dir = getattr(settings, "VARS", None)
    if not vars_dir:
        return global_vars
    if not os.path.exists(vars_dir):
        logger.debug(f"VARS directory {vars_dir} does not exist, skipping global vars")
        return global_vars

    yaml_files = find_yaml_files(vars_dir)
    logger.debug(f"Loading global vars from {len(yaml_files)} files in {vars_dir}")

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as stream:
                file_vars = yaml.safe_load(stream)
                if file_vars:
                    logger.debug(f"Loading vars from {os.path.basename(yaml_file)}")
                    global_vars = deep_merge(global_vars, file_vars)
        except yaml.YAMLError as exc:
            error_msg = f"Invalid YAML syntax in vars file '{yaml_file}'"
            if hasattr(exc, "problem_mark"):
                mark = exc.problem_mark
                error_msg += f" at line {mark.line + 1}, column {mark.column + 1}"
            if hasattr(exc, "problem"):
                error_msg += f": {exc.problem}"
            if hasattr(exc, "context"):
                error_msg += f" ({exc.context})"
            logger.error(error_msg)
        except FileNotFoundError:
            logger.error(f"Vars file not found: {yaml_file}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"Error loading vars from {yaml_file}: {exc}")

    return global_vars

