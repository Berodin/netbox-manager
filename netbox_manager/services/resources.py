# SPDX-License-Identifier: Apache-2.0
"""Service layer for processing resource files and orchestration."""

import concurrent.futures
import glob
import os
import re
import sys
import tempfile
import time
from copy import deepcopy
from itertools import groupby
from typing import Any, Dict, Iterable, List, Optional, Tuple

import ansible_runner
import git
from loguru import logger
import typer
import yaml

from netbox_manager.ansible.playbook import (
    create_ansible_playbook,
    create_netbox_task,
    create_uri_task,
    inventory,
)
from netbox_manager.config import settings, validate_netbox_connection
from netbox_manager.dtl import NetBox, Repo
from netbox_manager.logging_utils import init_logger
from netbox_manager.utils.data import (
    extract_device_names_from_task,
    get_leading_number,
    should_skip_task_by_device_filter,
    should_skip_task_by_filter,
)
from netbox_manager.utils.yaml_utils import deep_merge, load_global_vars


def build_inventory() -> Dict[str, Any]:
    """Return a fresh inventory with the current Python interpreter configured."""
    inv = deepcopy(inventory)
    inv["all"]["hosts"]["localhost"]["ansible_python_interpreter"] = sys.executable
    return inv


def _load_yaml(file: str, fail_fast: bool) -> Optional[Any]:
    """Load YAML content from a file with defensive error handling."""
    try:
        with open(file) as fp:
            return yaml.safe_load(fp)
    except yaml.YAMLError as exc:
        error_msg = f"Invalid YAML syntax in file '{file}'"
        if hasattr(exc, "problem_mark"):
            mark = exc.problem_mark
            error_msg += f" at line {mark.line + 1}, column {mark.column + 1}"
        if hasattr(exc, "problem"):
            error_msg += f": {exc.problem}"
        if hasattr(exc, "context"):
            error_msg += f" ({exc.context})"
        logger.error(error_msg)
    except FileNotFoundError:
        logger.error(f"File not found: {file}")
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Error reading file '{file}': {exc}")

    if fail_fast:
        raise typer.Exit(1)
    return None


def _validate_yaml_structure(file: str, data: Any, fail_fast: bool) -> bool:
    """Ensure YAML content is a list and not empty."""
    if data is None:
        logger.warning(f"File '{file}' is empty or contains only comments")
        return False
    if not isinstance(data, list):
        logger.error(
            f"Invalid YAML structure in file '{file}': Expected a list of tasks, got {type(data).__name__}"
        )
        if fail_fast:
            raise typer.Exit(1)
        return False
    return True


def _apply_filters(
    key: str,
    value: Dict[str, Any],
    task_filter: Optional[str],
    device_filters: Optional[List[str]],
) -> bool:
    """Return True if the task should be skipped due to filters."""
    if task_filter and should_skip_task_by_filter(key, task_filter):
        logger.debug(f"Skipping task of type '{key}' (filter: {task_filter})")
        return True

    if device_filters:
        device_names = extract_device_names_from_task(key, value)
        if should_skip_task_by_device_filter(device_names, device_filters):
            if device_names:
                logger.debug(
                    f"Skipping task with devices '{device_names}' (device filters: {device_filters})"
                )
            else:
                logger.debug(
                    f"Skipping task of type '{key}' with no device reference (device filters active)"
                )
            return True
    return False


def _build_task_from_entry(
    key: str,
    value: Dict[str, Any],
    register_var: Optional[str],
    ignore_errors: bool,
    task_filter: Optional[str],
    device_filters: Optional[List[str]],
) -> Optional[Dict[str, Any]]:
    """Create a single Ansible task entry from YAML input."""
    if key == "vars":
        return {"vars": value}
    if key == "debug":
        task: Dict[str, Any] = {"ansible.builtin.debug": value}
        if register_var:
            task["register"] = register_var
        if ignore_errors:
            task["ignore_errors"] = True
        return task
    if key == "uri":
        return create_uri_task(value, register_var, ignore_errors)

    if _apply_filters(key, value, task_filter, device_filters):
        return None

    return create_netbox_task(key, value, register_var, ignore_errors)


def _gather_tasks_from_data(
    data: List[Dict[str, Any]],
    task_filter: Optional[str],
    device_filters: Optional[List[str]],
    ignore_errors: bool,
    fail_fast: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Convert YAML list into vars + tasks while applying filters."""
    template_vars = load_global_vars()
    template_tasks: List[Dict[str, Any]] = []

    for idx, rtask in enumerate(data):
        if not isinstance(rtask, dict):
            logger.error(
                f"Invalid task structure in YAML at index {idx}: Expected a dictionary, got {type(rtask).__name__}"
            )
            if fail_fast:
                raise typer.Exit(1)
            continue
        if not rtask:
            logger.warning(f"Empty task in YAML at index {idx}, skipping")
            continue

        register_var = rtask.pop("register", None)
        try:
            key, value = next(iter(rtask.items()))
        except StopIteration:
            logger.warning(
                f"Task at index {idx} has no content after removing 'register' field, skipping"
            )
            continue

        task_entry = _build_task_from_entry(
            key, value, register_var, ignore_errors, task_filter, device_filters
        )
        if task_entry:
            if task_entry.get("vars"):
                template_vars = deep_merge(template_vars, task_entry["vars"])
            elif key != "vars":
                template_tasks.append(task_entry)

    return template_tasks, template_vars


def _run_playbook_for_file(
    file: str,
    template_vars: Dict[str, Any],
    template_tasks: List[Dict[str, Any]],
    dryrun: bool,
    show_playbooks: bool,
    fail_fast: bool,
    verbose: bool,
) -> None:
    """Render and execute (or show) the playbook for a file."""
    if not template_tasks:
        logger.info(f"No tasks to execute in {file} after filtering")
        return

    playbook_resources = create_ansible_playbook(
        os.path.basename(file), template_vars, template_tasks
    )

    if show_playbooks:
        print(f"# Playbook for {file}")
        print(playbook_resources)
        print()
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".yml", delete=False
        ) as temp_file:
            temp_file.write(playbook_resources)

        if dryrun:
            logger.info(f"Skip the execution of {file} as only one dry run")
            return

        verbosity = 3 if verbose else None
        result = ansible_runner.run(
            playbook=temp_file.name,
            private_data_dir=temp_dir,
            inventory=build_inventory(),
            cancel_callback=lambda: None,
            verbosity=verbosity,
            envvars={
                "ANSIBLE_STDOUT_CALLBACK": "ansible.builtin.default",
                "ANSIBLE_CALLBACKS_ENABLED": "ansible.builtin.default",
                "ANSIBLE_STDOUT_CALLBACK_RESULT_FORMAT": "yaml",
            },
        )
        if fail_fast and result.status == "failed":
            logger.error(
                f"Ansible playbook failed for {file}. Exiting due to --fail option."
            )
            raise typer.Exit(1)


def handle_file(
    file: str,
    dryrun: bool,
    task_filter: Optional[str] = None,
    device_filters: Optional[List[str]] = None,
    fail_fast: bool = False,
    show_playbooks: bool = False,
    verbose: bool = False,
    ignore_errors: bool = False,
) -> None:
    """Process a single YAML resource file and execute corresponding Ansible playbook."""
    logger.info(f"Handle file {file}")
    data = _load_yaml(file, fail_fast)
    if not _validate_yaml_structure(file, data, fail_fast):
        return

    template_tasks, template_vars = _gather_tasks_from_data(
        data,
        task_filter=task_filter,
        device_filters=device_filters,
        ignore_errors=ignore_errors,
        fail_fast=fail_fast,
    )
    _run_playbook_for_file(
        file=file,
        template_vars=template_vars,
        template_tasks=template_tasks,
        dryrun=dryrun,
        show_playbooks=show_playbooks,
        fail_fast=fail_fast,
        verbose=verbose,
    )


def process_device_and_module_types(
    settings_attr: str, skip_flag: bool, type_name: str
) -> None:
    """Process device types or module types with common logic."""
    library_path = getattr(settings, settings_attr, None)
    if not library_path or skip_flag:
        return

    logger.info(f"Manage {type_name}")
    dtl_repo = Repo(library_path)
    dtl_netbox = NetBox(settings)

    try:
        files, vendors = dtl_repo.get_devices()
        types_data = dtl_repo.parse_files(files)

        dtl_netbox.create_manufacturers(vendors)

        if type_name == "devicetypes":
            dtl_netbox.create_device_types(types_data)
        else:
            dtl_netbox.create_module_types(types_data)

    except FileNotFoundError:
        logger.error(f"Could not load {type_name} in {library_path}")


def discover_resource_files(
    resources_dir: str, limit: Optional[str] = None
) -> List[str]:
    """Discover and return sorted list of resource files."""
    files = []

    for extension in ["yml", "yaml"]:
        try:
            top_level_files = glob.glob(os.path.join(resources_dir, f"*.{extension}"))
            if limit:
                top_level_files = [
                    f for f in top_level_files if os.path.basename(f).startswith(limit)
                ]
            files.extend(top_level_files)
        except FileNotFoundError:
            logger.error(f"Could not load resources in {resources_dir}")

    vars_dirname = None
    vars_dir = getattr(settings, "VARS", None)
    if vars_dir:
        vars_dirname = os.path.basename(vars_dir)

    try:
        for item in os.listdir(resources_dir):
            item_path = os.path.join(resources_dir, item)
            if os.path.isdir(item_path) and (not vars_dirname or item != vars_dirname):
                if limit and not item.startswith(limit):
                    continue
                if not re.match(r"^\d+-.+", item):
                    continue

                dir_files = []
                for extension in ["yml", "yaml"]:
                    dir_files.extend(glob.glob(os.path.join(item_path, f"*.{extension}")))
                dir_files.sort(key=lambda f: os.path.basename(f))
                files.extend(dir_files)
    except FileNotFoundError:
        pass

    return files


def run(
    always: bool = True,
    debug: bool = False,
    dryrun: bool = False,
    limit: Optional[str] = None,
    parallel: Optional[int] = 1,
    skipdtl: bool = False,
    skipmtl: bool = False,
    skipres: bool = False,
    wait: bool = True,
    filter_task: Optional[str] = None,
    include_ignored_files: bool = False,
    filter_device: Optional[list[str]] = None,
    fail_fast: bool = False,
    show_playbooks: bool = False,
    verbose: bool = False,
    ignore_errors: bool = False,
) -> None:
    """Entry point for the run command."""
    start = time.time()

    init_logger(debug)
    validate_netbox_connection()

    changed_files: List[str] = []
    if not always:
        try:
            config_repo = git.Repo(".")
        except git.exc.InvalidGitRepositoryError:
            logger.error(
                "If only changed files are to be processed, the netbox-manager must be called in a Git repository."
            )
            raise typer.Exit()

        commit = config_repo.head.commit
        changed_files = [str(item.a_path) for item in commit.diff(commit.parents[0])]

        if debug:
            logger.debug(
                "A list of the changed files follows. Only changed files are processed."
            )
            for file_name in changed_files:
                logger.debug(f"- {file_name}")

        if not skipdtl and not any(
            f.startswith(settings.DEVICETYPE_LIBRARY) for f in changed_files
        ):
            logger.debug(
                "No file changes in the devicetype library. Devicetype library will be skipped."
            )
            skipdtl = True

        if not skipmtl and not any(
            f.startswith(settings.MODULETYPE_LIBRARY) for f in changed_files
        ):
            logger.debug(
                "No file changes in the moduletype library. Moduletype library will be skipped."
            )
            skipmtl = True

        if not skipres and not any(
            f.startswith(settings.RESOURCES) for f in changed_files
        ):
            logger.debug("No file changes in the resources. Resources will be skipped.")
            skipres = True

    if skipdtl and skipmtl and skipres:
        raise typer.Exit()

    if wait:
        logger.info("Wait for NetBox service")
        playbook_wait = f"""
- name: Wait for NetBox service
  hosts: localhost
  gather_facts: false

  tasks:
    - name: Wait for NetBox service REST API
      ansible.builtin.uri:
        url: "{settings.URL.rstrip('/')}/api/"
        headers:
          Authorization: "Token {str(settings.TOKEN)}"
          Accept: application/json
        status_code: [200]
        validate_certs: {not settings.IGNORE_SSL_ERRORS}
      register: result
      retries: 60
      delay: 5
      until: result.status == 200 or result.status == 403
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            with tempfile.NamedTemporaryFile(
                mode="w+", suffix=".yml", delete=False
            ) as temp_file:
                temp_file.write(playbook_wait)

            ansible_result = ansible_runner.run(
                playbook=temp_file.name,
                private_data_dir=temp_dir,
                inventory=build_inventory(),
                cancel_callback=lambda: None,
                envvars={
                    "ANSIBLE_STDOUT_CALLBACK": "ansible.builtin.default",
                    "ANSIBLE_CALLBACKS_ENABLED": "ansible.builtin.default",
                    "ANSIBLE_STDOUT_CALLBACK_RESULT_FORMAT": "yaml",
                },
            )
            if (
                "localhost" in ansible_result.stats["failures"]
                and ansible_result.stats["failures"]["localhost"] > 0
            ):
                logger.error("Failed to establish connection to netbox")
                raise typer.Exit()

    process_device_and_module_types("DEVICETYPE_LIBRARY", skipdtl, "devicetypes")
    process_device_and_module_types("MODULETYPE_LIBRARY", skipmtl, "moduletypes")

    if not skipres:
        logger.info("Manage resources")
        files = discover_resource_files(settings.RESOURCES, limit)
        files_filtered = (
            [f for f in files if f in changed_files] if not always else files
        )

        if not include_ignored_files:
            ignored_files = getattr(
                settings, "IGNORED_FILES", ["000-external.yml", "000-external.yaml"]
            )
            files_filtered = [
                f
                for f in files_filtered
                if not any(os.path.basename(f) == ignored_file for ignored_file in ignored_files)
            ]
            if debug and len(files) != len(files_filtered):
                logger.debug(
                    f"Filtered out {len(files) - len(files_filtered)} ignored files"
                )

        files_filtered.sort(key=get_leading_number)
        files_grouped = []
        for _, group in groupby(files_filtered, key=get_leading_number):
            files_grouped.append(list(group))

        for group in files_grouped:  # type: ignore[assignment]
            if group:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=parallel
                ) as executor:
                    futures = [
                        executor.submit(
                            handle_file,
                            file,
                            dryrun,
                            filter_task,
                            filter_device,
                            fail_fast,
                            show_playbooks,
                            verbose,
                            ignore_errors,
                        )
                        for file in group
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        future.result()

    end = time.time()
    logger.info(f"Runtime: {(end-start):.4f}s")
