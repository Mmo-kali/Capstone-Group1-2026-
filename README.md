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

### Week 2 - (2026-05-04 to 2026-05-10)
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

### Week 3 - (2026-05-11 to 2026-05-17)
**User Information Enumeration Added**  
Implemented Active Directory user enumeration with `bloodyAD` to collect attributes (sAMAccountName, pwdLastSet, description), group memberships, and store them in the database for display in the UI.

**Domain Admins Enumeration Added**  
Added a Domain Admins collection workflow, including storage in a new `domain_admins` table and a UI section to display collected members.

**Machine Account Quota Visibility**  
Pulled and displayed `ms-DS-MachineAccountQuota` with a dedicated tooltip explaining its security impact.

**Dangerous Group Intelligence Expanded**  
Expanded the dangerous group list and enhanced tooltips with detailed descriptions and documentation links.

**User Info UI Enhancements**  
Added UI improvements for group pills, tooltips, and warnings to improve visibility of privilege and risk.

**Commit references:**  
- [added user information enumeration](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/131b1723965132ce59a4687072fac83b002fb9d7)  
- [User info collection + dangerous group UI + DB updates](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/e5f481960ae3cc673a7c7101c446f145c0177d8d)  
- [User info collection + dangerous group UI + DB updates (Part 2)](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/60dba38aa9d7f55fee14c4ae8947e6845b027269)
---

### Week 4 - (2026-05-18 to 2026-05-24)

- **Pass-the-Hash (PTH) authentication support added**
  - Added NTLM hash input to saved profiles (`ntlm_hash`).
  - Added auth method selection (Password vs NTLM Hash) in exploit workflows.
  - Integrated NTLM-hash auth into:
    - Kerberoast (`impacket-GetUserSPNs -hashes`)
    - AS-REP Roast (`impacket-GetNPUsers -hashes`)
    - DCSync (`impacket-secretsdump -hashes`)
    - bloodyAD-based checks/actions (`-p :<ntlm_hash> -f rc4`)

- **DACL abuse functionality added (GenericAll / writable object abuse)**
  - Added `/writable` workflow to enumerate writable/GenericAll targets using `bloodyAD get writable --right WRITE`.
  - Added exploitation step to reset target user passwords using `bloodyAD set password`.
  - Added UI page to display discovered GenericAll targets and trigger password-change action per target.

- **DCSync rights detection improved**
  - Added bloodyAD-based DCSync privilege check by resolving and parsing `nTSecurityDescriptor`.
  - Detects replication rights tied to DCSync and reports if user has required access.

- **DCSync output handling and hash workflow improvements**
  - Added parsing/storage of dumped NTLM hashes from DCSync results.
  - Stored hashes can be used in the cracking workflow and for follow-on authentication techniques.

_Commit references (last 7 days):_  
- [Delete sessionresume_SagDRCBg](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/896086d7ee6be4133087e1d109f8e8f4eeb139aa)  
- [Update .gitignore](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/72e3a0eadfd255b69ecd03a85095068f0e79d72f)

---

## Week 7 - (2026-06-15 to 2026-06-21)

### UI upgrade implemented across the Flask application
- Updated main route handling in `app/routes/main.py`.
- Overhauled shared styling in `app/static/css/style.css`.
- Added frontend interaction updates in `app/static/js/script.js`.

### Attack workflow pages refreshed
- Redesigned templates for:
  - AS-REP Roast
  - DCSync
  - Kerberoast
  - Writable Objects
  - Zerologon
  - Vault
- Updated `base.html` and `index.html` to improve shared layout and homepage presentation.

### Supporting backend modules adjusted
- Modified:
  - `app/utils/asreproast.py`
  - `app/utils/dcsync.py`
  - `app/utils/kerberoast.py`
  - `app/utils/zerologon.py`
- These backend updates appear to support the revised interface and workflow behavior.

### Project artifacts updated
- Updated local SQLite database file: `app/db/app.db`.
- Regenerated Python cache files as part of the commit.

### Commit references (last 7 days)
- [UI upgrade](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/0ded0d35ce2d8bb6593081ec24f2d09c0ec81939)

--- 
## Week 8 - (2026-06-28 to 2026-07-04)
- Fixed the asset information to display information about all user groups.
- DB update to add schema for admin info. 
- Updated the Admin information to display in an organized format.

### Latest Commit
- [DB Update](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/9cd2615e5868ef7c3b0594a264c45a25e2fc80c3)
- [minor fix: fix domain admin collection issue](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/7335265cd3df51dfb62df0163db962ff7a6c82e6)

---
## Week 9 - (2026-07-05 to 2026-07-11)

### Credential verification added to Vault workflow
- Implemented LDAP-based credential validation from the Vault after hash cracking.
- Added domain/profile inference logic to map cracked users to the correct saved AD profile.
- Added LDAP bind verification using `ldap3` with NTLM authentication in backend route handling.

### Vault page action and UX updates
- Added a new Vault action button to verify cracked credentials for the selected user.
- Updated button/action wording from **"Verify LDAP Bind"** to **"Verify Credential"** for clearer UI messaging.
- Updated success/failure response messages to use credential-verification terminology.

### Backend and dependency updates
- Updated `app/routes/main.py` with:
  - credential verification helper flow
  - vault domain inference from Kerberoast/AS-REP hash formats
  - profile lookup and LDAP bind checks
- Updated `app/templates/vault.html` to support the new verification action.
- Added `ldap3>=2.9` to `requirements.txt`.

### Commit references (last 7 days)
- [minor change: added credential check using ldap bind](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/2e43593f4c41ef2318cb2e091d584e7b6f8105dd)
- [minor update: button update](https://github.com/Mmo-kali/Capstone-Group1-2026-/commit/300d5a05dbcda67670862c5416f92f5c499349f8)

---
