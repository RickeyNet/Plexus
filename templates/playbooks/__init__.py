"""
Auto-import all playbook modules so their @register_playbook decorators fire.

Files starting with an underscore (e.g. ``_common.py``) are treated as
internal helper modules and are NOT auto-imported as playbooks.  They
contain shared utilities used by the real playbook modules and should
not appear in the UI's playbook list.
"""
import importlib
import os
import sys

# Make sure the project root is importable so playbooks can do
# ``from routes.runner import ...``.  __file__ lives three levels deep:
#   <project_root>/templates/playbooks/__init__.py
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Walk this directory and import every .py file.  Each playbook module
# uses ``@register_playbook`` at import time, which is what makes it
# show up in the UI's playbook picker.
_dir = os.path.dirname(__file__)
for filename in os.listdir(_dir):
    # Skip non-Python files, this __init__, and any underscore-prefixed
    # helper modules (e.g. ``_common.py``) that are not playbooks.
    if not filename.endswith(".py"):
        continue
    if filename == "__init__.py" or filename.startswith("_"):
        continue
    module_name = filename[:-3]
    importlib.import_module(f"templates.playbooks.{module_name}")
