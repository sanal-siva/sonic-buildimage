"""SONiC show plugin entry point."""
from guardian.cli import show

def register(root_command):
    root_command.add_command(show, name="security")
