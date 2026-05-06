"""
LogLM web application package.

Why this file exists
--------------------
Without __init__.py, Python 3 treats the ``app/`` directory as a *namespace
package* (PEP 420).  Namespace packages have ``__file__ = None`` and
``__spec__.origin = None``, which is why the interpreter reports
``(unknown location)`` in ImportError tracebacks.

When the FastAPI/Uvicorn process runs from WORKDIR /app (inside Docker) and
launches ``uvicorn app.main:app``, Python adds ``/app`` (the web/ tree) to
``sys.path[0]``.  Under those conditions ``from app import opscenter`` must
find ``/app/app/opscenter.py`` as a *submodule* of a *regular* package.

Namespace packages make submodule lookup non-deterministic when:
  * A stale ``__pycache__/`` directory from a prior build exists.
  * The package is imported from multiple path entries simultaneously.
  * The interpreter encounters the package for the first time via an
    attribute access (``from pkg import name``) rather than a full
    qualified import (``import pkg.name``).

Making ``app`` a regular package (by adding this __init__.py) ensures:
  1. ``app.__file__`` resolves to this file — no more ``(unknown location)``.
  2. ``from app import opscenter`` reliably loads ``app/opscenter.py``.
  3. ``from app import hitl``      reliably loads ``app/hitl.py``.
  4. All existing ``from app import auth, observability`` calls are unaffected.

This file intentionally contains NO executable code — all submodules are
imported lazily (on demand) by the callers in main.py.  Adding eager imports
here would re-introduce circular-import risk and increase cold-start latency.
"""
