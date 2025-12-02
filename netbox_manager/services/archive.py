# SPDX-License-Identifier: Apache-2.0
"""Archive import/export helpers."""

import os
import platform
import subprocess
import tarfile
import tempfile
from typing import List

import git
from loguru import logger
import typer

from netbox_manager.config import settings
from netbox_manager.logging_utils import init_logger


def _gather_directories() -> List[str]:
    """Collect configured directories that exist."""
    directories = []
    if settings.DEVICETYPE_LIBRARY and os.path.exists(settings.DEVICETYPE_LIBRARY):
        directories.append(settings.DEVICETYPE_LIBRARY)
    if settings.MODULETYPE_LIBRARY and os.path.exists(settings.MODULETYPE_LIBRARY):
        directories.append(settings.MODULETYPE_LIBRARY)
    if settings.RESOURCES and os.path.exists(settings.RESOURCES):
        directories.append(settings.RESOURCES)
    return directories


def export_archive(image: bool = False, image_size: int = 100) -> None:
    """Export devicetypes, moduletypes, and resources to netbox-export.tar.gz."""
    init_logger()

    directories = _gather_directories()
    if not directories:
        logger.error("No directories found to export")
        raise typer.Exit(1)

    output_file = "netbox-export.tar.gz"
    image_file = "netbox-export.img"
    mount_point = "/tmp/netbox-export-mount"

    try:
        commit_info_file = None
        try:
            repo = git.Repo(".")
            commit = repo.head.commit

            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".txt"
            ) as commit_info:
                commit_info_file = commit_info.name
                commit_info.write("NetBox Manager Export - Git Commit Information\n")
                commit_info.write("=" * 50 + "\n\n")
                commit_info.write(f"Commit Hash:   {commit.hexsha}\n")
                commit_info.write(
                    f"Commit Date:   {commit.committed_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
                )
                commit_info.write(f"Branch:        {repo.active_branch.name}\n")

            logger.info(f"Git commit info captured: {commit.hexsha[:8]}")
        except git.exc.InvalidGitRepositoryError:
            logger.warning("Not a git repository - skipping commit info in export")
        except Exception as exc:
            logger.warning(f"Could not retrieve git commit info: {exc}")

        with tarfile.open(output_file, "w:gz") as tar:
            if commit_info_file and os.path.exists(commit_info_file):
                logger.info("Adding COMMIT_INFO.txt to archive")
                tar.add(commit_info_file, arcname="COMMIT_INFO.txt")

            for directory in directories:
                logger.info(f"Adding {directory} to archive")
                tar.add(directory, arcname=os.path.basename(directory))

        if commit_info_file and os.path.exists(commit_info_file):
            os.remove(commit_info_file)

        logger.info(f"Export completed: {output_file}")

        if image:
            if platform.system() != "Linux":
                logger.error("Creating ext4 images is only supported on Linux systems")
                raise typer.Exit(1)

            logger.info(f"Creating {image_size}MB ext4 image: {image_file}")
            os.system(
                f"dd if=/dev/zero of={image_file} bs=1M count={image_size} 2>/dev/null"
            )
            os.system(f"mkfs.ext4 -q {image_file}")
            os.makedirs(mount_point, exist_ok=True)

            logger.info(f"Mounting image to {mount_point}")
            mount_result = os.system(f"sudo mount -o loop {image_file} {mount_point}")

            if mount_result != 0:
                logger.error("Failed to mount image (requires sudo)")
                raise typer.Exit(1)

            try:
                logger.info("Copying tarball to image")
                os.system(f"sudo cp {output_file} {mount_point}/")
                os.system("sync")
                logger.info("Unmounting image")
                os.system(f"sudo umount {mount_point}")
            except Exception as exc:
                logger.error(f"Error during copy: {exc}")
                os.system(f"sudo umount {mount_point}")
                raise

            os.rmdir(mount_point)
            os.remove(output_file)

            logger.info(
                f"Export completed: {image_file} ({image_size}MB ext4 image containing {output_file})"
            )

    except Exception as exc:
        logger.error(f"Failed to create export: {exc}")
        raise typer.Exit(1)


def import_archive(input_file: str, destination: str) -> None:
    """Import and sync content from a netbox-export.tar.gz file to local directories."""
    init_logger()

    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        raise typer.Exit(1)

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            logger.info(f"Extracting {input_file} to temporary directory")
            with tarfile.open(input_file, "r:gz") as tar:
                tar.extractall(temp_dir)

            for item in os.listdir(temp_dir):
                source_path = os.path.join(temp_dir, item)
                if not os.path.isdir(source_path):
                    continue

                target_path = os.path.join(destination, item)
                logger.info(f"Syncing {item} to {target_path}")

                os.makedirs(target_path, exist_ok=True)

                rsync_cmd = [
                    "rsync",
                    "-av",
                    "--delete",
                    f"{source_path}/",
                    f"{target_path}/",
                ]

                result = subprocess.run(rsync_cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    logger.error(f"rsync failed: {result.stderr}")
                    raise typer.Exit(1)

                logger.info(f"Successfully synced {item}")

            logger.info("Import completed successfully")

        except Exception as exc:
            logger.error(f"Failed to import: {exc}")
            raise typer.Exit(1)

