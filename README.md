### Tatou — Group 03

A PDF watermarking platform built with Flask and MariaDB.

Setup

Requires Python 3.12, Docker Compose, and Bash (Linux or WSL). From the repository root:

# Dependencies

python3.12 -m venv .venv
source .venv/bin/activate
pip install -e './server[dev]' pytest-cov

# Run and deploy

Create a root .env file with your deployment values:

MARIADB_ROOT_PASSWORD=change-me
MARIADB_USER=tatou
MARIADB_PASSWORD=change-me
SECRET_KEY=replace-with-a-long-random-secret
FLAG_2=local-test
RMAP_SOURCE_DOCUMENT_ID=1
RMAP_WATERMARK_KEY=change-me
RMAP_SERVER_PASSPHRASE=

chmod +x server/entrypoint.sh
docker compose up --build -d
docker compose logs -f server

Open http://localhost:5000, register, log in, and upload a PDF. Select Watermark to create a personalised copy.

Check the running API:

curl http://localhost:5000/healthz

Confirm "db_connected": true. 

# Unit tests

With the virtual environment active, run:

python -m pytest server/test/test_watermarking_all_methods.py server/test/test_erik_watermark.py -v

# API tests

python -m pytest server/test/test_api.py server/test/test_document_authorization.py server/test/test_rmap_identity.py -v

These use Flask’s test client and isolated test resources; a running deployment is not required. RMAP testing covers identity validation during initiation, not the complete handshake.

# Coverage analysis

python -m pytest --cov


API endpoint documentation is available in server/API.md.


