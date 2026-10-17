SecureGate — Secure Telemetry/Command Validation Simulator

This is a local educational prototype that validates synthetic JSON telemetry
and harmless simulated commands. It has no real device integration and never
executes commands.

For Windows installation, virtual environment setup, dashboard startup, test
instructions, architecture, schema, demo steps, and limitations, see README.md.

Quick start from this project folder:

  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  python -m pip install -r requirements.txt
  python app.py

Open http://127.0.0.1:5000/ in your browser. Run tests with:

  python -m unittest -v
