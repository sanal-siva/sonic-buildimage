"""Registration helpers for sonic-utilities plugin loaders."""
from guardian.cli import config, show

def register_config(root):
    root.add_command(config, name="security")

def register_show(root):
    root.add_command(show, name="security")
