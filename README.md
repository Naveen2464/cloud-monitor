# Cloud Computing Project

This repository contains several self-contained demo applications for log monitoring, dashboarding, and alerting. It includes a cloud-ready Flask dashboard, ELK integration components, and sample logging pipelines.

## Repository Contents

- `cloud/` — Primary demo application with Flask UI, ELK integration, and log forwarding helpers.
- `dashboard/` — Dashboard-focused example with templates and session/log views.
- `log-monitoring-project/` — Additional log monitoring examples and Docker Compose references.
- `project_folder/` — Miscellaneous demo resources, sample configs, and startup files.

## What This Project Demonstrates

- user authentication and session logging via Flask
- alert generation for brute-force and login events
- ELK stack integration with Filebeat and Logstash
- dashboard and monitoring views for logs, alerts, and sessions
- logging to both a local file (`app.log`) and console output

## Prerequisites

- Python 3.8+ (recommended)
- pip
- Docker & Docker Compose (for ELK stack testing)
- (Windows) PowerShell or Git Bash for script execution

## Running the Cloud Monitor Demo

1. Open a terminal and switch to the `cloud` folder:

```powershell
cd c:\Users\navee\OneDrive\Desktop\cloud_computing_project\cloud
```

2. Create and activate a Python virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

3. Start the Flask application:

```powershell
python app.py
```

4. Open the dashboard in your browser:

- `http://127.0.0.1:5000`

The app also listens on `0.0.0.0:5000`, so it is reachable from other hosts if network access is allowed.

## Default Demo Credentials

The app prints sample login credentials on startup and the following valid accounts are available by default:

- `alice` / `password123`
- `bob` / `securepass`
- `admin` / `admin123`

## Log Files and Troubleshooting

- Application logs are written to `cloud/app.log`.
- Errors and login activity are also emitted to the console by default.
- If you see the message `WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.`, that means the app is running in Flask development mode.

For production, deploy the app with a WSGI server such as Gunicorn, uWSGI, or a managed platform instead of `python app.py`.

## Starting ELK

The `cloud/elk` folder includes ELK setup files and helper scripts. To start them locally:

```powershell
cd cloud/elk
docker-compose up -d
```

After ELK starts, configure Filebeat and Logstash using the included YAML files in `cloud/elk/filebeat/filebeat.yml` and `cloud/elk/logstash/config/logstash.conf`.

## Project Structure

Common files found in example folders:

- `app.py` — Flask application entry point
- `alert_monitor.py` — Monitoring and alerting script
- `database.py` — Local storage and authentication helper
- `elk_sender.py` — Event forwarding to Elasticsearch
- `requirements.txt` — Python dependency list
- `docker-compose.yml` — Container orchestration example
- `filebeat.yml` / `logstash.conf` — Logging pipeline examples
- `templates/` — HTML templates for the web UI

## Best Practices

- Do not store secrets in source control.
- Use environment variables or encrypted secret management for production configuration.
- Validate ELK connection status before sending production events.
- Use a separate production database and secure the app behind HTTPS.

## Contributing

Contributions are welcome.

- Open an issue for large changes.
- Submit pull requests with descriptive titles and clear implementation details.

## License

No license is included by default. Add a `LICENSE` file if you want to define usage terms.

## Support

If you need help, open an issue in this repository.
