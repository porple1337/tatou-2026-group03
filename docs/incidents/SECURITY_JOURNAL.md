# Security journal

## Entry template

- Date detected:
- What happened:
- Evidence:
- Impact:
- Actions taken:

## 2026-09-11 — flag_1 captured

**Detected:** 2026-09-11 16:32
**What Happened:** Recieved an email alerting us of our flag_1 being captured
**Evidence:** We hadn't included our flag files in .gitignore and they were made public by mistake
**Impact:** We got our flag stolen.
**Actions taken:** We included "flag" in .gitignore to make sure it doesn't get uploaded to the repository. We also deleted the git history since the history would still show the flag values.

## 2026-09-15 — flag_1 captured

**Detected:** 2026-09-15 20:55
**What Happened:** We got sent an automated e-mail informing us of our flag_1 got captured.
**Evidence:** We documented nmap scans, and also intrusion into our database. We could not determine the method of intrusion but SQL injection and default credentials were considered as possible explanations, but the available evidence was insufficient to establish the intrusion method.
**Impact:** We got our flag stolen.
**Actions taken:** The teacher's email confirms the flag capture, but the available evidence does
not establish the request, account, or vulnerability used. Several serious
weaknesses were corrected after detection, including missing ownership checks,
concatenated SQL, shell-backed watermark execution, and unsafe upload handling.
These were real risks, but this record does not claim that a specific one was
the proven entry path. 

## 2026-10-13 — flag_3 captured

**Detected:** 2026-10-13 20:55
**What Happened:** We got sent an automated e-mail informing us of our flag_3 got captured.
**Evidence:** We found that there were multiple Mr_Important users created with the exact name as the original file owner.
**Impact:** We got our flag stolen.
**Actions taken:** We promptly deleted these users and started working on a fix. We identified an authorization flaw in /api/list-versions and /api/list-all-versions: access was checked using usernames, allowing accounts with the same name as a legitimate owner to retrieve that owner’s watermarked-document links. We changed both endpoints to check document ownership against the authenticated user’s unique account ID. Duplicate usernames therefore no longer grant access to another account’s version listings. We also replaced the compromised FLAG_3 value in its PDF.  A unique-username database constraint was implemented as an additional safeguard.

## 2026-10-14 — flag_1 captured

**Detected:** 2026-10-14 09:11
**What Happened:** Recieved an email alerting us of our flag_1 being captured.
**Evidence:** At this point we had limited logging and we were unable to find the vulnerability used. After further inspection of the flag capture 2026-10-16 we believe the same method of attack was used for this capture aswell.
**Impact:** Our flag was stolen.
**Actions taken:** Rotated flag value.

## 2026-10-16 — flag_1 captured

**Detected:** 2026-10-16 12:18
**What Happened:** Recieved an email alerting us of our flag_1 being captured.
**Evidence:** From the security.log we can see that there were successful logins made by an ip, 10.100.11.15 (user_id=3) right before our flag was captured. Viewing this users uploaded files in the database we find that they've uploaded a large number of .pkl files. These were inspected in the containers storage and were found to contain a payload. It invokes Python’s exec during unpickling in api/load-plugin and runs a script that can expose our /app/flag thorugh an exception.
**Impact:** Our flag was stolen.
**Actions taken:** We disabled the /api/load-plugin since it's unsafe in its current form. And rotated the flag value.


Here are the four actions/bug fixes taken for increased security:
### 1. Document authorization and database query

- **Action:** Require authentication and ownership for document operations,
  and parameterize the document lookup.
- **Owner:** NattensK
- **Reference:** `2c19e0d9a0439c465a05ce8333ac2e447bfa5e8e`
- **Verification:** The cross-user deletion test returned `404` and confirmed that the target document remained in the database.
- **Status:** Implemented and verified locally for document deletion.

### 2. Shell-backed watermark execution

- **Action:** Remove shell and subprocess execution from the watermark method.
- **Owner:** Erik
- **Reference:** `67509e5873b45d95db917640136f0d7d4b3a48d6`
- **Verification:** Source diff shows the removal; regression test still needed.
- **Status:** Implemented; verification remains open.

### 3. PDF upload handling

- **Action:** Harden PDF validation, generated filenames, storage paths, and
  upload-size handling.
- **Owner:** Omar
- **Reference:** `c2da248ddc4d90e380f069e4d08fa8772b780dde`
- **Verification:** Negative upload tests still needed.
- **Status:** Implemented; verification remains open.

### 4. Automated pytest execution

- **Action:** Run pytest automatically for pushes and pull requests.
- **Owner:** Erik
- **Reference:** `68d4891`
- **Verification:** The workflow was corrected to run pytest from the `server/` directory. The local suite completed with 11 passed and 6 skipped; an Actions result has not yet been recorded.
- **Status:** Implemented locally; CI confirmation remains open.


### 5. Cross-user document authorization regression test

- **Action:** Added an automated test proving that one authenticated user cannot delete a document owned by another user.
- **Owner:** SAMM specialist - Jens
- **Reference:** 
- **Verification:** `test_user_cannot_delete_another_users_document` authenticated as User 2 and attempted to delete a document owned by User 1. The endpoint returned `404`, and a database query confirmed that the document remained present. The complete local suite reported 11 passed and 6 skipped.
- **Status:** Implemented and verified locally; GitHub Actions confirmation remains open.


### 6. Session-signing key configuration

- **Action:** Replaced the default SECRET_KEY with a private, randomly generated value supplied through the server environment to prevent token forgery using the known default.

- **Owner:** Erik

- **Reference:** None

- **Verification:** Confirm the deployed server uses the new key and rejects tokens signed with the previous key.

- **Status:** Confirmed the new deployment used the correct key.


### 7. Disabled unsafe endpoint api/load-plugin 

- **Action:** Disabled api/load-plugin since it allowed execution of python script during .pkl deserialization.

- **Owner:** Erik

- **Reference:** c03a1fa7d8dc2007a636922d71ebc9f6bee1bff8

- **Verification:** Ensure api/load-plugin endpoint returns "error": "Plugin loading is disabled".

- **Status:** Pending


### Deployments ###

# Initial deployment 
Date: 2026-09-11
State reference: 078e8bc49cb3e2b80b9253d89ebe80d30add442c

# First fixes deployment
Date: 2026-09-17
State reference: e5a910083472e4d4122867d7c2cf815e6ec60377

# Phase I deployment
Date: 2026-09-25
State reference: d8a6ccd372bc76d322149af4034d11ec438b0d7e

# SECRET_KEY security fix deployment
Date: 2026-10-12
State reference: None. Fixed on the server.

# Monitor security
Date: 2026-10-13
State reference: 310bb998d5b03a94d471c2a2b259d3b2b101bb38

# Final deployment (Phase II)
Date: 2026-10-16
State reference: This commit
