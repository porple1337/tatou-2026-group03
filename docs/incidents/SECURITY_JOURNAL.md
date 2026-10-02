# Security journal

## Entry template

- Date detected:
- What happened:
- Evidence:
- Impact:
- Actions taken:


## 2026-09-15 — flag_1 captured

**Detected:** 2026-09-15 20:55
**What Happened:** We got sent an automated e-mail informing us of our flag_1 got captured.
**Evidence:** We documented nmap scans, and also intrusion into our database. We could not determine the method of intrusion but we deducted that it most likely was sql injection or usage of default login credentials. Logs and screenshots are stored outside of git for security reasons.
**Impact:** We got our flag stolen.
**Actions taken:** The teacher's email confirms the flag capture, but the available evidence does
not establish the request, account, or vulnerability used. Several serious
weaknesses were corrected after detection, including missing ownership checks,
concatenated SQL, shell-backed watermark execution, and unsafe upload handling.
These were real risks, but this record does not claim that a specific one was
the proven entry path. 

Here are the four actions taken:
### 1. Document authorization and database query

- **Action:** Require authentication and ownership for document operations,
  and parameterize the document lookup.
- **Owner:** NattensK
- **Reference:** `2c19e0d9a0439c465a05ce8333ac2e447bfa5e8e`
- **Verification:** Security-specific behavioral test still needed.
- **Status:** Implemented; verification remains open.

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
- **Verification:** Local suite completed with 10 passed and 6 skipped; an
  Actions result has not been recorded.
- **Status:** Implemented; security coverage remains open.