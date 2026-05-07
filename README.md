# Capstone-Group1-2026- (First Half Progress)

## Group Members
- Michael Nolk [@Mmo-kali](https://github.com/Mmo-kali) | [Linkedin](https://www.linkedin.com/in/michaelnolk/)
- Micah Joshua Rahardjo [@Gikyon](https://github.com/Gikyon) | [Linkedin](https://www.linkedin.com/in/micahrahardjo/)
- Orlando Companioni Castro [@OrlandoCompC](https://github.com/OrlandoCompC) | [Linkedin](https://www.linkedin.com/in/orlando-companioni/)
- Prajwal Nautiyal [@PrajwalNa](https://github.com/PrajwalNa) | [Linkedin](https://www.linkedin.com/in/prajwal-n-19205624a/)


## What’s been done (First Half of Capstone)

### 1) Web GUI (Flask)
- Built a Flask web app with a simple UI to collect AD/domain details.
- Main input form collects:
  - Username
  - Password
  - Domain
  - Domain Controller IP (DC IP)
  - Domain Controller FQDN (DC FQDN)
- Saves submitted values in a session so they can be reused across pages.
- Pages/routes implemented:
  - `/` Main form + output view
  - `/kerberoast` Kerberoast page (check/exploit)
  - `/asreproast` AS-REP Roast page (check/exploit)
  - `/dcsync` DCSync page (check/exploit)
  - `/user-info` Displays stored session values
  - `/health` Health check endpoint

### 2) Kerberoasting (Check + Exploit)
- Kerberoast **Check**: lists accounts/services with SPNs.
- Kerberoast **Exploit**: requests Kerberos TGS tickets and extracts `$krb5tgs$` hashes.
- Uses bundled script: `app/utils/tools/GetUserSPNs.py`

### 3) AS-REP Roasting (Check + Exploit)
- AS-REP Roast **Check**: identifies users that may be roastable (no pre-auth).
- AS-REP Roast **Exploit**: requests AS-REP and extracts `$krb5asrep$` hashes.
- Uses bundled script: `app/utils/tools/GetNPUsers.py`

### 4) DCSync (Privilege Check + Dump Attempt)
- DCSync **Check**: determines if the account likely has DCSync rights (detects access denied). (STILL IN PROGRESS)
- DCSync **Exploit**: runs a secrets dump and returns parsed credential output.
- Uses bundled script: `app/utils/tools/secretsdump.py`

### 5) Output / Results Display
- Output page displays submitted values with the password masked.
- Attack pages display results and basic status/error messages when creds are missing.

### 6) Setup / Install Helper
- `setup.py` bootstrap script:
  - Creates a `.venv`
  - Upgrades pip tooling
  - Installs dependencies from `requirements.txt`
- Dependencies include Flask + WTForms + Impacket.
