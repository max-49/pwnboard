#!/usr/bin/env python3
"""Convert an older board.json (rows of hosts) to the version 2 format.

    python3 scripts/convert_board.py board.json              # print the result
    python3 scripts/convert_board.py board.json new.json     # write a new file
    python3 scripts/convert_board.py board.json --in-place   # rewrite it, keeping board.json.bak

PWNBoard converts old files itself when it starts, so this is only needed to get a file in
the new format, for example to edit it by hand. See "board.json" in doc/config.md.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwnboard.core.board_format import BoardError, normalize_board  # noqa: E402


def convert(raw):
    """Return (version 2 board, warnings) for a board in either format."""
    board = normalize_board(raw)
    warnings = []
    if "board" in raw:
        # Row names must be unique in the new format, so repeated or missing ones were changed
        for row, machine in zip(raw["board"], board["machines"]):
            if row.get("name") != machine:
                warnings.append(f"row {row.get('name')!r} was renamed {machine!r}")
    return board, warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert an older board.json to the version 2 format.")
    parser.add_argument("input", help="the board file to convert")
    parser.add_argument("output", nargs="?", help="where to write the result (default: print it)")
    parser.add_argument("--in-place", action="store_true",
                        help="rewrite the input file, after saving a copy as <input>.bak")
    parser.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    args = parser.parse_args(argv)

    if args.in_place and args.output:
        parser.error("use either an output file or --in-place, not both")

    try:
        with open(args.input) as fil:
            raw = json.load(fil)
        board, warnings = convert(raw)
    except FileNotFoundError:
        print(f"{args.input}: no such file", file=sys.stderr)
        return 1
    except ValueError as e:  # BoardError and invalid JSON
        print(f"{args.input}: {e}", file=sys.stderr)
        return 1

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    text = json.dumps(board, indent=2) + "\n"

    if args.in_place:
        backup = args.input + ".bak"
        shutil.copy2(args.input, backup)
        # Write into the existing file rather than replacing it, so a Docker bind mount of
        # board.json keeps pointing at it
        with open(args.input, "w") as fil:
            fil.write(text)
        print(f"Rewrote {args.input} (the old file is saved as {backup})", file=sys.stderr)
    elif args.output:
        if Path(args.output).exists() and not args.force:
            print(f"{args.output} already exists; use --force to overwrite it", file=sys.stderr)
            return 1
        with open(args.output, "w") as fil:
            fil.write(text)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    print(f"{len(board['teams'])} teams, {len(board['machines'])} machines, {len(board['hosts'])} hosts",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
