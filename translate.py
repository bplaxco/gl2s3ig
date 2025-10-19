"""
Translate Gitleaks rules to SSSIG format.
"""
import hashlib
import base64
import re
from re import _parser as re_parser
from regrp import split_regexp

import gitleaks
import sssig


def generate_sssig_id(gitleaks_id: str) -> str:
    """
    Generate an SSSIG ID from a Gitleaks ID.

    Format: S3IG[A-Z2-7]{16}
    Uses SHA256 hash of the gitleaks ID, base32 encoded, trimmed to 16 chars.
    """
    # Hash the gitleaks ID
    hash_bytes = hashlib.sha256(gitleaks_id.encode()).digest()
    # Base32 encode (uses A-Z and 2-7)
    b32 = base64.b32encode(hash_bytes).decode('ascii')
    # Take first 16 characters and prepend S3IG
    return f"S3IG{b32[:16]}"


def split_regex(regex: str, secret_group: int = 0) -> tuple[str | None, str, str | None]:
    """
    Split a gitleaks regex into prefix, target, and suffix based on the capture group.

    Args:
        regex: The full regex pattern
        secret_group: The capture group number (default 0)

    Returns:
        Tuple of (prefix_pattern, target_pattern, suffix_pattern)
    """
    prefix, target, suffix = split_regexp(secret_group, regex)
    return prefix or None, target, suffix or None


def translate_allowlist(allowlist: gitleaks.Allowlist) -> sssig.ExcludeFilter:
    """
    Translate a Gitleaks allowlist to an SSSIG ExcludeFilter.
    """
    filter_data = {
        "kind": sssig.FilterKind.EXCLUDE,
        "target_strings": allowlist.stopwords,
        "path_patterns": allowlist.paths,
    }

    # Map regexes based on regexTarget
    if allowlist.regexes:
        if allowlist.regexTarget == gitleaks.RegexTarget.LINE:
            filter_data["context_patterns"] = allowlist.regexes
        elif allowlist.regexTarget == gitleaks.RegexTarget.MATCH:
            filter_data["match_patterns"] = allowlist.regexes
        elif allowlist.regexTarget == gitleaks.RegexTarget.SECRET:
            filter_data["target_patterns"] = allowlist.regexes

    return sssig.ExcludeFilter(**filter_data)


def translate_rule(rule: gitleaks.Rule) -> sssig.Rule:
    """
    Translate a Gitleaks rule to an SSSIG rule.
    """
    # Generate SSSIG ID
    sssig_id = generate_sssig_id(rule.id)

    # Handle missing regex - for path-only rules, use a catch-all pattern
    if not rule.regex:
        if rule.path:
            # Path-only rule - match any content
            prefix, target, suffix = None, ".+", None
        else:
            raise ValueError(f"Rule {rule.id} has neither regex nor path pattern")
    else:
        # Split the regex pattern
        prefix, target, suffix = split_regex(rule.regex)

    # Create target
    target_obj = sssig.Target(
        prefix_pattern=prefix,
        pattern=target,
        suffix_pattern=suffix,
    )

    # Create meta
    meta = sssig.RuleMeta(
        name=rule.description or rule.id,
        description=rule.description,
        tags=rule.tags,
        report=not rule.skipReport if rule.skipReport is not None else True,
    )

    # Create filters
    filters = []

    # Add entropy filter if present
    if rule.entropy is not None:
        filters.append(sssig.RequireFilter(
            kind=sssig.FilterKind.REQUIRE,
            target_min_entropy=rule.entropy,
        ))

    # Add path filter if present
    if rule.path is not None:
        filters.append(sssig.RequireFilter(
            kind=sssig.FilterKind.REQUIRE,
            path_patterns=[rule.path],
        ))

    # Translate allowlists to exclude filters
    if rule.allowlists:
        for allowlist in rule.allowlists:
            filters.append(translate_allowlist(allowlist))

    # Create dependencies
    dependencies = None
    if rule.required:
        dependencies = [
            sssig.Dependancy(
                rule_id=generate_sssig_id(req.id),
                varname="match",  # TODO: Generate proper variable names
                within_lines=req.withinLines,
                within_columns=req.withinColumns,
            )
            for req in rule.required
        ]

    return sssig.Rule(
        id=sssig_id,
        meta=meta,
        target=target_obj,
        filters=filters or None,
        dependencies=dependencies,
    )


def translate_config(config: gitleaks.Config) -> sssig.Rules:
    """
    Translate a Gitleaks config to SSSIG rules.
    """
    return sssig.Rules(
        rules=[translate_rule(rule) for rule in config.rules]
    )
