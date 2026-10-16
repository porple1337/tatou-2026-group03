# Fuzzing findings from the local test

For my fuzzing specialization, I tested Tatou's document-deletion API. This
builds on the earlier SAMM test that checked whether one logged-in user could
delete another user's document. I wanted to see how the same endpoint handled
unusual document IDs and JSON bodies.

I used Hypothesis to generate requests and a valid test token so the requests
would reach the deletion code. The tests ran through Flask's test client. Each
example used a temporary PDF and an in-memory SQLite database with one test
document. I checked both the HTTP response and whether the document record
and file were unchanged after a rejected request. The campaign and run
instructions are in server/fuzz/.

## What I found before the fix

The local baseline had **three failing tests and one passing test**. These
were the three problems:

| ID | Input and result in the local test | Why it happened | What I changed |
| F01 | JSON true caused an AttributeError instead of a controlled response. | The code assumed every JSON body was an object and called .get() on a boolean. | Check that the body is an object before reading its id; otherwise return 400. |
| F02 | JSON {"id": false} returned 404 instead of rejecting the ID with 400. | Python converts False to 0 with int(False). The old conversion also accepted floats. | Accept only an integer or an ASCII decimal string, and reject booleans and floats. |
| F03 | JSON {"id": 18446744073709551616} returned 503 after a SQLite conversion error. | This value is 2^64, outside the range of Tatou's BIGINT UNSIGNED document IDs. | Check that the ID is between 1 and 2^64 - 1 before the database lookup. |

For F02, the baseline directly showed the false case. From Python's
conversion rules, true or 1.0 could also become ID 1, but I did not
observe an unauthorized deletion. The ownership check still limits which
document a user can delete. For F03, the error was observed with **SQLite**;
I have not tested whether MariaDB would return the same error.

The fourth test tried to delete user 1's document using user 2's valid test
token. It passed in the baseline: the request was rejected and the document
remained. I did not count that as a bug.

## After the fix

I added fixed regression cases in server/test/test_delete_fuzz_regressions.py
for the inputs above and for cross-user deletion. These check for the expected
400 or 404 response and that the database row and PDF stay unchanged. An
owner-success case checks that valid deletion still works.

With seed 20261012, the local fuzz campaign then reported **four passing
tests**: 250 accepted examples for each of the three broad input tests, plus
eight cross-user combinations. The selected fuzz and regression run reported
**20 passed**. The full regular server/test suite reported **27 passed,
6 skipped**. The 6 skipped are due to the small size of the test-PDF that the 
watermarking methods did not find suitable.


