# Fuzzing the document-delete endpoint

This is the fuzzing test I used for Tatou's document-delete API. It tries
different request bodies and document IDs, including requests from a user who
does not own the document. Hypothesis generates the inputs for the test.

The test does **not** contact the running Tatou container. It uses Flask's
test client, a temporary PDF and a fresh in-memory SQLite database. It also
uses test login tokens. Real files and MariaDB data are not changed.

## Run it

From the server folder, run these commands in Bash. Use a project-compatible Python environment; if the shell has
python3 but not python, replace python with python3. If pytest and
Hypothesis are already installed in that environment, skip the install lines:

bash
python -m pip install -e ".[dev]"
python -m pip install -r fuzz/requirements.txt
PYTHONPATH=src:test python -m pytest fuzz/test_delete_campaign.py \
  --hypothesis-seed=20261012 \
  --hypothesis-show-statistics \
  --basetemp=fuzz/results/pytest-tmp \
  -o addopts='' -q


To run the regular tests, including the fixed regression cases found through
fuzzing:

bash
PYTHONPATH=src:test python -m pytest test \
  --basetemp=fuzz/results/pytest-tmp -o addopts='' -q


## What counts as a problem?

The tests check the response and whether the document record and PDF stay
unchanged when a request should be rejected. They count unexpected server
errors, acceptance of an invalid document ID, or changes to another user's
document as failures. A normal 400 or 404 response does not count as a bug.

The main fuzzing tests try up to 250 generated examples each. The fuzzing
campaign is separate from the regular test/ suite; the fixed regression
tests are in test/.
