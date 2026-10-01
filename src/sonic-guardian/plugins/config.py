"""SONiC config plugin entry point."""
from guardian.cli import config

def register(root_command):
    root_command.add_command(config, name="security")
