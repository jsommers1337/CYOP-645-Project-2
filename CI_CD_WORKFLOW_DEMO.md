# Tracewatch CI/CD Workflow Demo

## Purpose

Tracewatch uses GitHub Actions to run repeatable quality checks when application code is pushed to `main` or proposed for merging into `main`. The workflow tests packet-analysis behavior, checks code quality with Pylint, and scans application source with Bandit. A failed job marks the workflow as failed and makes the issue visible in the repository's **Actions** tab.

This repository currently implements continuous integration (CI), not continuous delivery (CD): it does not package, publish, or deploy the desktop application. GitHub branch protection can be configured separately to require this workflow to pass before pull requests are merged; without that setting, Actions reports failures but does not reject a push by itself.

## Initial Tests

The tests in `tests/test_analyzer.py` build small packet sets, write them to temporary `.pcapng` files, and run the same analyzer used by the desktop app. This tests the parser and detection rules without requiring a real capture or network access.

1. **TCP scan and HTTP indicators:** creates SYN packets to 13 consecutive TCP ports and an HTTP `/login` request. Checks that a TCP port sweep and plaintext exposure are reported, and that the HTTP finding includes its Host and URI.
2. **Regular beacon timing:** creates eight UDP packets to one remote endpoint at 60-second intervals. Checks that the regular-interval heuristic identifies a possible beacon pattern.
3. **UDP scan attribution:** sends eight distinct UDP ports to each of two destinations. Checks that ports are not incorrectly combined across destinations into a UDP sweep finding.
4. **Empty capture:** checks that an empty file is handled and produces the informational “No configured heuristics triggered” finding.

Run the checks locally from the repository folder after activating the project environment and installing development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests
python -m pylint app.py analyzer.py tests/test_analyzer.py
python -m bandit -r app.py analyzer.py
```

The initial local verification passed all four unit tests, Pylint reported **10.00/10**, and Bandit reported **no issues identified**.

## Dependency Files

### `requirements.txt`

This is the runtime dependency list used by the application:

- `scapy>=2.6.1` reads packets from `.pcapng` captures.
- `matplotlib>=3.10` draws the I/O chart and embeds it in the Tkinter desktop window.
- `networkx>=3.4` lays out the directional flow graph.

These packages are needed to run the application; they are not development-only checks.

### `requirements-dev.txt`

This file includes the runtime dependencies with `-r requirements.txt`, then adds tools used for verification:

- `pylint>=3.3,<4` checks Python code quality and common programming errors. The upper bound keeps upgrades within the supported major release.
- `bandit>=1.8,<2` scans Python source for common security issues, also constrained to a major-version range.

Keeping these tools in a separate file means an application user can install runtime packages alone, while contributors and CI install both runtime and development tools.

## GitHub Actions Workflow

The workflow is `.github/workflows/tracewatch-quality.yml`.

| Component | Configuration | Purpose |
| --- | --- | --- |
| `name` | `tracewatch-quality` | Name displayed in the GitHub Actions tab. |
| `on.push` | Pushes to `main`, filtered to application code, tests, requirements, Pylint configuration, and this workflow file. | Runs checks when relevant changes are pushed. |
| `on.pull_request` | Pull requests targeting `main`, using the same path filters. | Checks proposed changes before merge. |
| `workflow_dispatch` | Manual trigger. | Allows a user to start the checks from the Actions tab. |
| `permissions` | `contents: read` | Gives the job read-only repository access. |
| `jobs.quality.runs-on` | `ubuntu-latest` | Selects GitHub's hosted Linux runner. |
| Checkout | `actions/checkout@v4` | Checks the repository code out onto the runner. |
| Python setup | `actions/setup-python@v5`, Python `3.12` | Provides a consistent Python runtime for CI. |
| Dependency installation | Upgrades pip, then installs `requirements-dev.txt`. | Installs application and verification dependencies. |
| Unit tests | `python -m unittest discover -s tests` | Exercises the four analyzer behavior cases. |
| Pylint | `python -m pylint app.py analyzer.py tests/test_analyzer.py` | Lints the application and tests; `.pylintrc` records the project policy. |
| Bandit | `python -m bandit -r app.py analyzer.py` | Recursively scans application modules for common security issues. |

The steps run in order. If dependency installation or any check exits unsuccessfully, later steps are skipped and the job is marked failed. GitHub records the run and its logs under **Actions**.

## Initial Pipeline Result

The first GitHub Actions run completed successfully: dependency installation, unit tests, Pylint, and Bandit all passed. The run is available at [tracewatch-quality run #1](https://github.com/jsommers1337/CYOP-645-Project-2/actions/runs/39145949740). It ran on commit `5313bad`; the subsequent commit `22aac42` changed only author/committer metadata, not the project files.

## Push and Review Process

After making a code change, run the local commands above, commit the changes, and push the branch. For a pull request, open it against `main` and review the workflow status and logs before merging. To make the workflow a merge gate, enable branch protection for `main` and require the `quality` check to pass.