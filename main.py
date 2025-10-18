#!./.venv/bin/python3
from argparse import ArgumentParser
from pathlib import Path


def new_parser() -> ArgumentParser:
    parser = ArgumentParser(
        program="gl2s3ig",
        description="Convert Gitleaks config to SSSIG rules",
    )
    parser.add_argument(
        "src", required=True, type=Path, help="source gitleals config.toml"
    )
    parser.add_argument(
        "dst", required=True, type=Path, help="destination SSSIG rules.yaml"
    )
    return parser


def main() -> None:
    args = new_parser().parse_args()


if __name__ == "__main__":
    main()
