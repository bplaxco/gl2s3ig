# Gl2S3IG (Gitleaks to SSSIG)

An experiment with converting Gitleaks config to the SSSIG format.

## Example Usage

```sh
# Sreate/sync the venv
uv sync

# Build the hyper scan regex compat check lib
make compile

# Run the conversion
./main.py tests/fixtures/gitleaks_8.27.0.toml ./sssig_rules.yaml
```
