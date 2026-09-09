# CI/CD integration

`scripts/ci-scan.py` drives L4L0's existing `lalo-gui` HTTP API
non-interactively: it launches a scan, polls until it finishes, saves the
SARIF report, and exits non-zero only when the worst **confirmed** finding
(adversarially reviewed, never just filed) meets or exceeds a severity
threshold you choose. An unconfirmed or open-proof-gap finding never fails
a build — it still lands in the SARIF output for a human to read.

This is a standalone script outside `src/lalo/`, not a new interactive
interface to L4L0 itself — `lalo-gui` stays the only way to actually run
and watch a scan; this script is automation glue a CI runner invokes.

```bash
python scripts/ci-scan.py \
  --target https://staging.example.com \
  --fail-on-severity high \
  --sarif-out l4l0-results.sarif
```

Options: `--base-url` (default `http://127.0.0.1:8000`), `--target`
(repeatable), `--mission`, `--fail-on-severity`
(`critical`/`high`/`medium`/`low`/`info`, omit to never fail the build),
`--sarif-out`, `--poll-interval-s`, `--timeout-s`.

## GitHub Actions

```yaml
name: L4L0 security scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - name: Start lalo-gui
        run: uv run lalo-gui &
      - name: Wait for lalo-gui
        run: |
          for i in $(seq 1 30); do
            curl -sf http://127.0.0.1:8000/ && break
            sleep 1
          done
      - name: Run L4L0 scan
        run: |
          uv run python scripts/ci-scan.py \
            --target https://staging.example.com \
            --fail-on-severity high \
            --sarif-out l4l0-results.sarif
      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: l4l0-results.sarif
```

## GitLab CI

```yaml
l4l0-scan:
  stage: test
  image: python:3.13-slim
  before_script:
    - pip install uv
    - uv sync
    - uv run lalo-gui &
    - |
      for i in $(seq 1 30); do
        curl -sf http://127.0.0.1:8000/ && break
        sleep 1
      done
  script:
    - >
      uv run python scripts/ci-scan.py
      --target https://staging.example.com
      --fail-on-severity high
      --sarif-out l4l0-results.sarif
  artifacts:
    reports:
      sast: l4l0-results.sarif
    when: always
```
