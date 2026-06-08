"""Tool subcommands.

Every module here exposes the same small interface so the CLI can register it
generically:

    NAME: str                     # subcommand name, e.g. "subfinder"
    HELP: str                     # one-line description
    add_arguments(parser)         # attach argparse options
    run(args) -> int              # execute; emit envelope; return exit code
"""
