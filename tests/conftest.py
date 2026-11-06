"""
conftest.py – Adds the project root to sys.path so that test modules can
import `api`, `modules`, `scanners`, and `config` without installing the
package.  Pytest discovers and executes this file automatically before any
test collection.
"""
import sys
import pathlib

# Project root is the parent of the `tests/` directory
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

