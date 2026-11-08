"""Allow ``python -m mailproof`` to behave exactly like the ``mailproof`` CLI."""

from .cli import main

raise SystemExit(main())
