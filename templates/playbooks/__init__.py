"""
Auto-import all playbook modules so their @register_playbook decorators fire.
"""
import os
import importlib
import sys

# Ensure the project root is on the path so 'routes.runner' can be imported
# Get project root (parent of templates directory)
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

_dir = os.path.dirname(__file__)
for filename in os.listdir(_dir):
    if filename.endswith(".py") and filename != "__init__.py":
        module_name = filename[:-3]
        importlib.import_module(f"templates.playbooks.{module_name}")
