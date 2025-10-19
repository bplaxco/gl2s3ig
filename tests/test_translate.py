import gitleaks
import translate
import sssig


def test_generate_sssig_id():
    """Test SSSIG ID generation from gitleaks ID."""
    # Test that it generates a valid format
    gitleaks_id = "test-rule-123"
    sssig_id = translate.generate_sssig_id(gitleaks_id)

    # Should start with S3IG
    assert sssig_id.startswith("S3IG")
    # Should be 20 characters total (S3IG + 16 chars)
    assert len(sssig_id) == 20
    # Should match the pattern
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in sssig_id[4:])

    # Test deterministic - same input should give same output
    assert translate.generate_sssig_id(gitleaks_id) == sssig_id

    # Different inputs should give different outputs
    assert translate.generate_sssig_id("different-id") != sssig_id


def test_translate_allowlist_with_stopwords():
    """Test translating an allowlist with stopwords."""
    allowlist = gitleaks.Allowlist(
        stopwords=["example", "test", "1234"],
    )

    filter_obj = translate.translate_allowlist(allowlist)

    assert isinstance(filter_obj, sssig.ExcludeFilter)
    assert filter_obj.kind == sssig.FilterKind.EXCLUDE
    assert filter_obj.target_strings == ["example", "test", "1234"]


def test_translate_allowlist_with_line_regexes():
    """Test translating an allowlist with LINE regexTarget."""
    allowlist = gitleaks.Allowlist(
        regexTarget=gitleaks.RegexTarget.LINE,
        regexes=["test.*pattern", "another.*regex"],
    )

    filter_obj = translate.translate_allowlist(allowlist)

    assert isinstance(filter_obj, sssig.ExcludeFilter)
    assert filter_obj.context_patterns == ["test.*pattern", "another.*regex"]
    assert filter_obj.match_patterns is None
    assert filter_obj.target_patterns is None


def test_translate_allowlist_with_match_regexes():
    """Test translating an allowlist with MATCH regexTarget."""
    allowlist = gitleaks.Allowlist(
        regexTarget=gitleaks.RegexTarget.MATCH,
        regexes=["match.*pattern"],
    )

    filter_obj = translate.translate_allowlist(allowlist)

    assert filter_obj.match_patterns == ["match.*pattern"]
    assert filter_obj.context_patterns is None
    assert filter_obj.target_patterns is None


def test_translate_allowlist_with_secret_regexes():
    """Test translating an allowlist with SECRET regexTarget."""
    allowlist = gitleaks.Allowlist(
        regexTarget=gitleaks.RegexTarget.SECRET,
        regexes=["secret.*pattern"],
    )

    filter_obj = translate.translate_allowlist(allowlist)

    assert filter_obj.target_patterns == ["secret.*pattern"]
    assert filter_obj.context_patterns is None
    assert filter_obj.match_patterns is None


def test_translate_allowlist_with_paths():
    """Test translating an allowlist with path patterns."""
    allowlist = gitleaks.Allowlist(
        paths=[".*\\.test$", "vendor/.*"],
    )

    filter_obj = translate.translate_allowlist(allowlist)

    assert filter_obj.path_patterns == [".*\\.test$", "vendor/.*"]


def test_translate_basic_rule():
    """Test translating a basic gitleaks rule."""
    gitleaks_rule = gitleaks.Rule(
        id="test-rule-1",
        description="Test Rule",
        regex="test.*pattern",
        tags=["test", "example"],
    )

    sssig_rule = translate.translate_rule(gitleaks_rule)

    assert isinstance(sssig_rule, sssig.Rule)
    assert sssig_rule.id.startswith("S3IG")
    assert sssig_rule.meta.name == "Test Rule"
    assert sssig_rule.meta.description == "Test Rule"
    assert sssig_rule.meta.tags == ["test", "example"]
    assert sssig_rule.target.pattern == "test.*pattern"


def test_translate_rule_with_entropy():
    """Test translating a rule with entropy."""
    gitleaks_rule = gitleaks.Rule(
        id="entropy-rule",
        description="Entropy Rule",
        regex="[a-z]+",
        entropy=3.5,
    )

    sssig_rule = translate.translate_rule(gitleaks_rule)

    assert sssig_rule.filters is not None
    # Find the entropy filter
    entropy_filters = [f for f in sssig_rule.filters if isinstance(f, sssig.RequireFilter) and f.target_min_entropy is not None]
    assert len(entropy_filters) == 1
    assert entropy_filters[0].target_min_entropy == 3.5


def test_translate_rule_with_path():
    """Test translating a rule with a path pattern."""
    gitleaks_rule = gitleaks.Rule(
        id="path-rule",
        description="Path Rule",
        regex="secret",
        path=".*\\.env$",
    )

    sssig_rule = translate.translate_rule(gitleaks_rule)

    assert sssig_rule.filters is not None
    # Find the path filter
    path_filters = [f for f in sssig_rule.filters if isinstance(f, sssig.RequireFilter) and f.path_patterns is not None]
    assert len(path_filters) == 1
    assert path_filters[0].path_patterns == [".*\\.env$"]


def test_translate_rule_with_allowlist():
    """Test translating a rule with an allowlist."""
    gitleaks_rule = gitleaks.Rule(
        id="allowlist-rule",
        description="Allowlist Rule",
        regex="password.*",
        allowlists=[
            gitleaks.Allowlist(
                stopwords=["example", "test"],
                regexTarget=gitleaks.RegexTarget.LINE,
                regexes=["#.*noqa"],
            )
        ],
    )

    sssig_rule = translate.translate_rule(gitleaks_rule)

    assert sssig_rule.filters is not None
    # Find exclude filters
    exclude_filters = [f for f in sssig_rule.filters if isinstance(f, sssig.ExcludeFilter)]
    assert len(exclude_filters) == 1
    assert exclude_filters[0].target_strings == ["example", "test"]
    assert exclude_filters[0].context_patterns == ["#.*noqa"]


def test_translate_rule_path_only():
    """Test translating a path-only rule (no regex)."""
    gitleaks_rule = gitleaks.Rule(
        id="path-only-rule",
        description="Path Only Rule",
        path=".*\\.p12$",
    )

    sssig_rule = translate.translate_rule(gitleaks_rule)

    # Should use a catch-all pattern
    assert sssig_rule.target.pattern == ".+"
    assert sssig_rule.target.prefix_pattern is None
    assert sssig_rule.target.suffix_pattern is None

    # Should have path filter
    path_filters = [f for f in sssig_rule.filters if isinstance(f, sssig.RequireFilter) and f.path_patterns is not None]
    assert len(path_filters) == 1
    assert path_filters[0].path_patterns == [".*\\.p12$"]


def test_translate_config():
    """Test translating a full gitleaks config."""
    config = gitleaks.Config(
        rules=[
            gitleaks.Rule(id="rule1", description="Rule 1", regex="pattern1"),
            gitleaks.Rule(id="rule2", description="Rule 2", regex="pattern2"),
        ]
    )

    sssig_rules = translate.translate_config(config)

    assert isinstance(sssig_rules, sssig.Rules)
    assert len(sssig_rules.rules) == 2
    assert all(r.id.startswith("S3IG") for r in sssig_rules.rules)
