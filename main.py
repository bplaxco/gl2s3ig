#!./.venv/bin/python3
from argparse import ArgumentParser
from pathlib import Path

import gitleaks


def new_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="gl2s3ig",
        description="Convert Gitleaks config to SSSIG rules",
    )
    parser.add_argument(
        "src", type=Path, help="source gitleals config.toml"
    )
    parser.add_argument(
        "dst", type=Path, help="destination SSSIG rules.yaml"
    )
    return parser


def main() -> None:
    args = new_parser().parse_args()

    # Load the gitleaks config
    with args.src.open("rb") as fp:
        config = gitleaks.load(fp)

    print(f"Loaded {len(config.rules)} rules from {args.src}")


if __name__ == "__main__":
    main()
