# Tracewatch Capture Analyzer

Tracewatch is an offline Python desktop application for reviewing `.pcapng` captures for network-security indicators. It uses Scapy for packet parsing, Tkinter for the desktop interface, and Matplotlib/NetworkX for visualizations.

## Run

Python 3.10 or newer is recommended. From this folder:

```powershell
python -m pip install -r requirements.txt
python app.py
```

Choose **Open .pcapng** to load a capture. The application reports heuristic findings, protocol totals, directional flows, and offers an I/O graph and a flow graph. Selecting a finding shows its evidence and a suggested investigation step.

## Checks included

- Cleartext HTTP, Telnet, and FTP compared with SSH and HTTPS/TLS traffic
- Large directional flows, using a one-megabyte minimum and 25% of capture bytes as the threshold
- TCP destination-port sweeps, UDP destination-port sweeps, and incomplete TCP handshakes
- HTTP Host and URI observations, with sensitive-path keywords highlighted for review
- Regular packet intervals between an endpoint pair as a possible beaconing pattern

These checks are triage heuristics, not a malware verdict. A packet capture can omit traffic, encrypted payloads, or handshake packets; the application does not perform TLS decryption, TCP stream reassembly, reputation lookups, or endpoint attribution. Validate findings against the capture context and other security telemetry. Captures stay local and are not uploaded.

## Tests

Run the focused analyzer tests with:

```powershell
python -m unittest discover -s tests
```

## GitHub Actions CI

The workflow at `.github/workflows/tracewatch-quality.yml` runs on pushes and pull requests targeting `main` when application code, tests, requirements, or CI configuration changes. It installs the development requirements, runs the unit tests, and checks the Python files with Pylint and Bandit. It can also be started manually from the repository's **Actions** tab.

Run the same checks locally before pushing:

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests
python -m pylint app.py analyzer.py tests/test_analyzer.py
python -m bandit -r app.py analyzer.py
```

To publish this existing project, first create a blank GitHub repository (do not initialize it with a README, `.gitignore`, or license), then run these commands in the project folder, substituting your repository URL:

```powershell
git init
git add .
git commit -m "Add Tracewatch capture analyzer"
git branch -M main
git remote add origin https://github.com/<username>/<repository>.git
git push -u origin main
```

The workflow result will appear in the repository's **Actions** tab. A failed check blocks a successful CI run; review its logs, fix the issue, and push a follow-up commit.