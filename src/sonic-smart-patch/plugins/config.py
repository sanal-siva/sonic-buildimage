"""SONiC config plugin entry point."""
from smart_patch.cli import config

def register(root_command):
    root_command.add_command(config, name="security")
