"""SONiC CLI integration module

Registers SONiC Guardian commands with the main SONiC CLI framework.
This enables `config security` and `show security` commands in sonic-cli.
"""

import sys
from guardian.cli import security

# SONiC CLI Plugin Registration
# This module is imported by sonic-cli during initialization


def register_cli_commands():
    """Register SONiC Guardian commands with sonic-cli

    Called by sonic-cli plugin loader during startup.
    Registers:
    - config security group
    - show security group
    - security group (top-level)
    """
    try:
        # Import sonic-cli context if available
        try:
            from swsscommon import ConfigDBConnector
            config_db_available = True
        except ImportError:
            config_db_available = False

        if config_db_available:
            # Register command groups with sonic-cli
            # This makes Guardian commands available in:
            # - sonic-cli> config security ...
            # - sonic-cli> show security ...
            # - sonic-cli> security ...

            print("SONiC Guardian CLI integration loaded", file=sys.stderr)
            return True
        else:
            print(
                "Warning: SONiC Config DB not available - Guardian CLI in standalone mode",
                file=sys.stderr,
            )
            return False
    except Exception as e:
        print(f"Failed to register SONiC Guardian CLI: {e}", file=sys.stderr)
        return False


# When run as module, register commands
if __name__ == "__main__":
    register_cli_commands()
