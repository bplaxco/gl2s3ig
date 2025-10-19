# Gl2S3IG (Gitleaks to SSSIG)

An experiment with converting Gitleaks config to the [SSSIG format](https://github.com/secret-scanning-sig/rules).

## Example Usage

```sh
# Create/sync the venv
uv sync

# Build the HyperScan regex compat check lib
make compile

# Run the conversion
./main.py tests/fixtures/gitleaks_8.27.0.toml ./sssig_rules.yaml
```
