"""
nemo-tollwarden — Tollwarden payment security for the NVIDIA NeMo Agent Toolkit.

Registers three NeMo functions (tollwarden_scan_payment, tollwarden_check_reputation,
tollwarden_report_counterparty) via the `nat.components` entry point. Importing this
package runs the registrations in `register.py`.

Tollwarden is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

__version__ = "0.1.0"

# Importing the register module runs the @register_function decorators. The
# nat.components entry point in pyproject.toml points here so the toolkit loads
# these functions on initialization.
from . import register  # noqa: F401,E402

__all__ = ["register", "__version__"]
