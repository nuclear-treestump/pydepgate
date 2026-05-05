"""pydepgate.__main__

Entry point for `python -m pydepgate`.

Delegates to the CLI module so `python -m pydepgate <args>` and
`python -m pydepgate.cli <args>` behave identically.
"""

from pydepgate.cli.main import main


if __name__ == "__main__":
    raise SystemExit(main())