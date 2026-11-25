"""Run asm_scanner_core's parser golden tests inside the backend suite.

The tests live with the package (backend/packages/asm_scanner_core/tests) so
they travel with it; CI runs ``pytest backend/tests``, so they are re-exported
here. Run them alone with
``PYTHONPATH=backend/packages/asm_scanner_core pytest backend/packages/asm_scanner_core/tests``.
"""

import importlib.util
from pathlib import Path

_PATH = (Path(__file__).resolve().parents[1] / "packages" / "asm_scanner_core" / "tests"
         / "test_parsers.py")
_spec = importlib.util.spec_from_file_location("asm_scanner_core_parser_golden", _PATH)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

globals().update({name: value for name, value in vars(_module).items() if name.startswith("test_")})
