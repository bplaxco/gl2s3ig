#!./.venv/bin/python3
import yaml
from argparse import ArgumentParser
from pathlib import Path

import gitleaks
import translate


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

    # Translate to SSSIG format
    sssig_rules = translate.translate_config(config)

    print(f"Translated {len(sssig_rules.rules)} rules to SSSIG format")

    # Write to destination
    with args.dst.open("w") as fp:
        yaml.dump(
            sssig_rules.model_dump(mode="json", exclude_none=True),
            fp,
            default_flow_style=False,
            sort_keys=False,
        )

    print(f"Wrote SSSIG rules to {args.dst}")


if __name__ == "__main__":
    main()
