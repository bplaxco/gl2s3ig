import gitleaks


def test_load_gitleaks_config():
    """Test loading a real Gitleaks config file."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    assert isinstance(config, gitleaks.Config)
    assert len(config.rules) > 0


def test_gitleaks_rule_basic_fields():
    """Test that basic rule fields are parsed correctly."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    # Find the ArgoCD JWT rule
    argocd_rule = next(r for r in config.rules if r.id == "nPY_Rcj4gzY")

    assert argocd_rule.description == "ArgoCD JWT"
    assert argocd_rule.regex is not None
    assert "type:secret" in argocd_rule.tags
    assert "imlzcyi6imfyz29jzc" in argocd_rule.keywords


def test_gitleaks_rule_with_entropy():
    """Test that rules with entropy are parsed correctly."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    # Find the AWS IAM rule which has entropy
    aws_rule = next(r for r in config.rules if r.id == "LAJoYTdoQH4")

    assert aws_rule.description == "AWS IAM Unique Identifier"
    assert aws_rule.entropy == 3.2
    assert aws_rule.keywords is not None


def test_gitleaks_rule_with_allowlist():
    """Test that rules with allowlists are parsed correctly."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    # Find a rule with an allowlist
    rules_with_allowlists = [r for r in config.rules if r.allowlists is not None]

    assert len(rules_with_allowlists) > 0

    # Check the allowlist structure
    rule = rules_with_allowlists[0]
    allowlist = rule.allowlists[0]

    assert isinstance(allowlist, gitleaks.Allowlist)
    assert allowlist.condition in (None, gitleaks.AllowlistCondition.AND, gitleaks.AllowlistCondition.OR)


def test_gitleaks_rule_with_path():
    """Test that rules with path patterns are parsed correctly."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    # Find rules with path patterns
    rules_with_paths = [r for r in config.rules if r.path is not None]

    assert len(rules_with_paths) > 0


def test_gitleaks_rule_with_required():
    """Test that rules with required dependencies are parsed correctly."""
    with open("tests/fixtures/gitleaks_8.27.0.toml", "rb") as fp:
        config = gitleaks.load(fp)

    # Find rules with required dependencies
    rules_with_required = [r for r in config.rules if r.required is not None]

    if len(rules_with_required) > 0:
        rule = rules_with_required[0]
        req = rule.required[0]

        assert isinstance(req, gitleaks.Required)
        assert req.id is not None
