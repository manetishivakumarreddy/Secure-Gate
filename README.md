# SecureGate: Secure Telemetry/Command Validation Simulator

SecureGate is a local educational simulator designed to demonstrate defensive validation of synthetic telemetry and command messages. It does not connect to any real infrastructure and never executes commands. The goal is to show how malformed, stale, duplicate, or unauthorized payloads are rejected before reaching downstream systems.

## Architecture

- `validator.py` - core validation engine, replay checks, and configurable policy definitions.
- `audit.py` - audit logger with in-memory stats, JSON export, CSV export, filtering, and clear support.
- `app.py` - local Flask dashboard and API endpoints.
- `schema.json` - documented synthetic message schema and policy baseline.
- `samples.json` - seeded valid and invalid examples.
- `templates/index.html` - dashboard shell.
- `static/styles.css` and `static/app.js` - UI styling and frontend behavior.
- `test_validator.py` - automated validation tests.

```text
Browser UI --JSON--> Flask API --> validator --> ACCEPT/REJECT + findings
                                  |       |
                                  |       +--> in-memory replay state
                                  +----------> audit.py --> securegate_audit.log
                                                (JSON Lines)
schema.json and samples.json -----------------> UI/API reference data
test_validator.py ----------------------------> same validator functions
```

## Message schema

The simulator accepts two top-level categories:

### Telemetry

```json
{
  "message_id": "MSG-101",
  "sender": "SENSOR-01",
  "message_type": "TELEMETRY",
  "timestamp": "2026-10-17T00:00:00+05:30",
  "sequence": 101,
  "payload": {
    "temperature": 28.5,
    "voltage": 12.2,
    "signal_strength": 85
  }
}
```

Required rules:
- `message_id`: non-empty string, unique while replay protection is enabled.
- `sender`: must be in the allowlist (`SENSOR-01`, `SENSOR-02`, `SENSOR-03`).
- `message_type`: must be `TELEMETRY`.
- `timestamp`: ISO 8601 string with timezone offset, not older than 300 seconds, not more than 60 seconds in the future.
- `sequence`: non-negative integer; must be newer than the last accepted value for the sender when replay protection is enabled.
- `payload.temperature`: numeric, between -40.0 and 120.0.
- `payload.voltage`: numeric, between 0.0 and 60.0.
- `payload.signal_strength`: integer, between 0 and 100.

For example, changing the accepted telemetry temperature to `180.0` produces a `NUMERIC_RANGE` rejection:

```json
{
  "message_id": "MSG-103",
  "sender": "SENSOR-01",
  "message_type": "TELEMETRY",
  "timestamp": "2026-10-17T00:00:00+05:30",
  "sequence": 103,
  "payload": {
    "temperature": 180.0,
    "voltage": 12.2,
    "signal_strength": 85
  }
}
```

### Commands

```json
{
  "message_id": "CMD-101",
  "sender": "CONTROL-01",
  "message_type": "COMMAND",
  "command": "STATUS_CHECK",
  "timestamp": "2026-10-17T01:30:00+05:30",
  "sequence": 101,
  "parameters": {}
}
```

Command fields and policy:
- `message_id`: non-empty string, unique among accepted messages while replay protection is enabled.
- `sender`: one of `CONTROL-01`, `OPS-CTRL`, or `GATEWAY-01`; sender must be authorized for the command.
- `message_type`: exactly `COMMAND`.
- `command`: one of `STATUS_CHECK`, `SENSOR_READ`, `DIAGNOSTIC_PING`, or `TELEMETRY_REQUEST`.
- `timestamp`: ISO 8601 with timezone, no older than 300 seconds and no more than 60 seconds in the future.
- `sequence`: non-negative integer, increasing per sender when replay protection is enabled.
- `parameters`: object. `STATUS_CHECK` permits no parameters (optional `include_health` boolean); `SENSOR_READ` requires `target_sensor`; `DIAGNOSTIC_PING` requires `target_sensor` and integer `detail_level` (1-3); `TELEMETRY_REQUEST` requires `target_sensor` and integer `duration_seconds` (1-120). Targets are `SENSOR-01`, `SENSOR-02`, or `SENSOR-03`.

The sender authorization matrix is:
- `CONTROL-01` and `OPS-CTRL`: all four permitted command names.
- `GATEWAY-01`: `STATUS_CHECK` and `TELEMETRY_REQUEST`.

The Command Simulator builds the valid example with a fresh timestamp when loaded. Its invalid example contains an unsupported command name. The editor submits its original text to the Flask server, including malformed JSON, so syntax errors are reported and audited without a browser-side validation shortcut.

Allowed command names:
- `STATUS_CHECK`
- `SENSOR_READ`
- `DIAGNOSTIC_PING`
- `TELEMETRY_REQUEST`

No command is ever executed. A successful result means only that the synthetic JSON passed the local validation rules.

## Local run instructions

### Check Python

Open a command prompt in the project folder and run:

```powershell
python --version
```

If `python` is not recognized, try:

```powershell
py --version
```

### Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Launch the dashboard

```powershell
python app.py
```

Then open the browser to `http://127.0.0.1:5000/`.

## Audit logging

Every validation attempt creates a local audit entry with:

- event ID
- message ID if available
- sender if available
- category
- timestamp of decision
- ACCEPT or REJECT result
- list of validation findings and rule IDs

The log is a local demonstration artifact and is not treated as a tamper-proof production system. It is stored in `securegate_audit.log` and can be filtered, searched, and exported from the dashboard.
Raw submitted editor text is recorded for validation attempts, including malformed JSON, to make rejection results auditable.

## Replay protection

Replay protection is implemented in memory to prevent duplicate message IDs and stale sequence numbers from being accepted. The in-memory state resets when the Python process restarts. This is intentionally local and educational.

## Authentication

A production-grade authentication mechanism is not implemented in this prototype. Authentication is documented as a future enhancement. If added, it would use a clearly labelled synthetic secret and standard-library HMAC validation rather than a custom or unverified mechanism.

## Testing

Run automated tests with:

```powershell
python -m unittest -v
```

The suite covers:
- valid telemetry acceptance
- valid command acceptance
- missing-field and malformed JSON rejection
- unsupported command and unauthorized sender rejection
- invalid parameter and numeric range rejection
- stale timestamp and replay detection
- audit entries for accepted, rejected, and malformed submissions

## Limitations

- Synthetic validation only.
- No real device, network, or command execution.
- Replay tracking is in memory only.
- Browser/CLI interactions are local and educational.

This simulator is intentionally limited to demonstrate safe validation behavior and decision logging in a controlled environment.

## Windows setup from a fresh machine

Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/windows/) if it is not already installed. During setup, select **Add Python to PATH**.

Open PowerShell or the VS Code terminal in the project folder, then check the installation:

```powershell
python --version
```

If Windows does not recognize `python`, use the Python launcher:

```powershell
py --version
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this for the current terminal only, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Install the web-server dependency and run the dashboard:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/`. The server binds only to the local loopback interface. Stop it with **Ctrl+C**.

If using the launcher, replace `python` with `py` in these commands. From a new terminal, activate the environment again before launching.

## Run and demonstrate the tests

Run the automated test suite from the project directory:

```powershell
python -m unittest -v
```

The dashboard's **Test Lab** runs that same `test_validator.py` suite and displays its actual unittest output. Tests use a fixed injected clock and isolated replay state so timestamp and replay checks are repeatable. Seeded samples include valid telemetry and commands, missing fields, malformed JSON, incorrect types, range errors, unauthorized senders, unsupported commands, and stale/future timestamps. Tests additionally verify duplicate IDs and replayed sequence numbers.

## Judge demo script

1. Start SecureGate and open the local dashboard.
2. Load the `valid` telemetry sample and validate it; confirm **ACCEPT**.
3. Load `invalid_range`, validate it, and inspect the `NUMERIC_RANGE` finding.
4. Load the malformed sample and validate it; confirm a `JSON_SYNTAX` rejection is recorded.
5. Select a valid command sample and validate it; confirm the UI explicitly says it was not executed.
6. Search/filter the audit log, open **View** for an event, then export JSON or CSV.
7. Run the Test Lab and show the actual unittest summary.
8. Clear the audit log only after confirming; this also resets the in-memory replay window.

## Anticipated judge questions

- **Does this authenticate the sender?** No. Sender allowlisting is a validation policy, not cryptographic identity verification. Optional authentication is intentionally omitted.
- **Are the temperature and voltage limits operational recommendations?** No. They are illustrative, synthetic demo values.
- **Can a command reach a device?** No. The application has no device integration and never executes commands.
- **Does replay state survive restarts?** No. It is in-memory and resets when the application restarts or when the audit clear action is confirmed.
- **Is the audit log tamper-proof?** No. It is a local JSON Lines demo log, not a production audit service.
- **What would production require?** A threat model, authenticated identities and key management, durable replay storage, protected centralized logging, operationally reviewed policies, and independent security testing.

## Project files

```text
app.py                 Local Flask server and JSON API
validator.py           Shared validation engine and replay policy
audit.py               Local JSON Lines audit log and exports
schema.json            Machine-readable message schema and illustrative policies
samples.json           Seeded valid/invalid telemetry and command examples
test_validator.py      Deterministic unittest suite
templates/index.html   Dashboard sections
static/styles.css      Responsive dashboard styles
static/app.js          Browser UI and API integration
requirements.txt       Flask dependency
securegate.py          Optional terminal demonstration
```

The browser submits raw JSON to the server; JavaScript does not replace server-side validation. Requests larger than 1 MiB are rejected. Audit entries include submitted message data for this local synthetic prototype; do not submit real or confidential data.
