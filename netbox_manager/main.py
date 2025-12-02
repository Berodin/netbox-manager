# SPDX-License-Identifier: Apache-2.0
"""Entry point for netbox-manager CLI."""

from netbox_manager.cli.app import app, main

__all__ = ["app", "main"]

if __name__ == "__main__":
    main()

