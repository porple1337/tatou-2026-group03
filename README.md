### Tatou — Group 03

A PDF watermarking platform built with Flask and MariaDB.

From root

# Dependencies

pip install -e './server[dev]' pytest-cov

# Run and deploy

docker compose up --build -d

Open http://localhost:5000, register, log in, and upload a PDF. Select Watermark to create a personalised copy.

Check the running API:

curl http://localhost:5000/healthz

Confirm "db_connected": true. 

# All tests

python -m pytest

# Unit tests

python -m pytest server/test/test_watermarking_all_methods.py server/test/test_erik_watermark.py -v

# API tests

python -m pytest server/test/test_api.py server/test/test_document_authorization.py server/test/test_rmap_identity.py -v

# Coverage analysis

python -m pytest --cov


API endpoint documentation is available in server/API.md.


