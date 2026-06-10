# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


### ⚠️ BREAKING CHANGES

#### Passkey Storage Format Change (2026-05-18)

**Passkey files now split into two separate files:**
- `.passkey` - Contains encrypted credential data
- `.stash` - Contains encrypted hash header (230 bytes)

**Migration Required:**
- Old single-file format is **NOT supported**
- You **MUST regenerate** all passkey files before upgrading
- Old passkey files will be ignored by the system

**What to do:**
1. Back up your existing passkey files (optional)
2. Delete old `.passkey` files from `~/.fido/` (or `$FIDO_HOME`)
3. Re-register your passkeys with websites/applications
4. New passkeys will automatically use the two-file format

---
