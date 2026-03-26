# Secrets

This directory holds secret files referenced by `docker-compose.yml`.

Create the following files before running `docker-compose up`:

```
secrets/api_key.txt
secrets/operator_key.txt
secrets/challenger_key.txt
```

Each file should contain the corresponding secret value as plain text (no trailing newline).

**Do not commit actual secret files.** They are ignored by `.gitignore`.
