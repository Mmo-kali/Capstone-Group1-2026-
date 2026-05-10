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
  - `/vault` Cracking Station for obtained hashes

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

***

# What was completed in the second term 

### Week 2 - (2026-05-10)
- **Major Feature: Hashcat Integration Added**  
  Integrated Hashcat into the application, enabling users to perform password hash cracking directly through the Cracking Station. This significantly expands the tool’s capabilities for automated hash analysis and validation.

- **Added a new endpoint for the Cracking Station:**  
  Implemented an additional endpoint to support Cracking Station features, allowing efficient processing and analysis of obtained hashes.

- **Added flushing mechanism and improved cracking workflow:**  
  Introduced a flushing mechanism and enhancements to the hash cracking process for more reliable results.

- **Database implemented:**  
  Set up and integrated a database to support persistent storage of application data.

- **Repository cleanup:**  
  Removed outdated or unnecessary files to keep the codebase clean.

_Commit references:_  
- [readme update: Added a new endpoint for the Cracking Station](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/0e7f5a4286d0963912898cc1529690218df641ff)  
- [added flushing mechanism and cracking](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/d4cd171b7fe9b523f1f5d4537cadf8852392d37c)  
- [database implemented](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/285a68f6d12cce846e93536291b9eb0a370a941c)  
- [Delete junk](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/f8767e0cdad0918b852bca812c37ab837fe79eb1)

---
