# MYX AI (Windows Edition) — Git History Cleanup Plan & Execution Guide

**Application:** MYX AI by Midhun Krishnan  
**Classification:** DEVSECOPS & SOURCE CONTROL HARDENING  
**Status:** **PENDING USER APPROVAL** (Local backup verified; rewrite staged)  
**Date:** November 15, 2026  
**Repository:** `https://github.com/midhunkrishnan-131/myx-ai-windows.git`  
**Stand-alone Secure Bundle Backup:** `c:\Users\midhu\OneDrive\Desktop\BBX\myx-ai-git-backup-20261115.bundle` (VERIFIED)  
**Internal Backup Branch:** `backup-pre-hardening-20261115` (VERIFIED)  

---

## 1. Executive Summary & Problem Definition

In historical commits of this repository prior to commit `c35a271`, sensitive files containing user data and test databases were committed to the Git index:
- `backend/registered_users.json` (Historical commits: `5421de0`, `bc6e6a5`)
- `backend/myx_local_test.db` (Historical commits: `4a28b22`, `1b0fff2`)
- Compiled Python artifacts: `backend/app/auth/__pycache__/password.cpython-313.pyc`, `backend/app/database/__pycache__/init_db.cpython-313.pyc`

While these files have been untracked (`git rm --cached`) and deleted from the active working tree, their file blobs and commit snapshots persist in Git history. Anyone cloning the repository with `--depth` or fetching all objects could inspect past commits to extract these files.

Per development safety rules, **Git history has NOT been rewritten automatically and no force-push has been executed.** This document provides the complete, tested execution plan for permanently purging these files across all historical commits once approved.

---

## 2. Pre-Execution Verification & Backup Status

Before touching any Git references, two independent layers of full backups were created:

1. **Standalone Git Bundle (External to Workspace):**
   - **Path:** `c:\Users\midhu\OneDrive\Desktop\BBX\myx-ai-git-backup-20261115.bundle`
   - **Verification Command:** `git bundle verify "c:\Users\midhu\OneDrive\Desktop\BBX\myx-ai-git-backup-20261115.bundle"`
   - **Status:** **VERIFIED OK** (Preserves complete commit tree, objects, and all 4 branch references).
2. **Local Safety Branch:**
   - **Branch:** `backup-pre-hardening-20261115`
   - **Status:** Stored locally in `.git/refs/heads/`. **Note:** This branch contains sensitive historical commits and must **NOT** be pushed to remote GitHub.

---

## 3. Targeted Sensitive Files for Removal

| Path | Historical Commits Detected | Sensitive Data Contained |
|:---|:---|:---|
| `backend/registered_users.json` | `5421de0`, `bc6e6a5` | Historical user records, emails, password hashes |
| `backend/myx_local_test.db` | `4a28b22`, `1b0fff2` | Local development SQLite database |
| `backend/app/auth/__pycache__/*.pyc` | `4a28b22` | Compiled bytecode artifacts |
| `backend/app/database/__pycache__/*.pyc` | `4a28b22` | Compiled bytecode artifacts |

---

## 4. Step-by-Step Cleanup Procedure (Using `git-filter-repo`)

`git-filter-repo` is the official tool recommended by the Git core development team for high-speed, safe history rewrites (superseding `git filter-branch` and BFG).

### Step 1: Install `git-filter-repo`
Run in terminal:
```powershell
& ".\backend\.venv\Scripts\python.exe" -m pip install git-filter-repo
```

### Step 2: Execute Inverted Path Purge Across All Branches
This command rewrites the commit history to completely expunge the targeted paths from every commit in the repository:
```powershell
& ".\backend\.venv\Scripts\python.exe" -m git_filter_repo --invert-paths `
  --path backend/registered_users.json `
  --path registered_users.json `
  --path backend/myx_local_test.db `
  --path myx_local_test.db `
  --path-glob "**/__pycache__/*" `
  --force
```

### Step 3: Expire Reflogs and Prune Dangling Blobs
```powershell
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### Step 4: Verify Clean History
Verify that no commit in the entire repository contains references to the sensitive files:
```powershell
# 1. Check registered_users.json
git log --all --full-history -- "**/registered_users.json"
# (Must return zero lines)

# 2. Check myx_local_test.db
git log --all --full-history -- "**/myx_local_test.db"
# (Must return zero lines)

# 3. Check for any remaining sqlite files
git log --all --full-history --name-only | Select-String -Pattern "\.sqlite|\.db"
# (Must return zero lines)
```

---

## 5. Consequences & Handling Existing Clones and Remote Repository

> [!WARNING]
> **CRITICAL CONSEQUENCES OF FORCE-PUSHING:**
> 1. **Commit SHAs Will Change:** Every commit downstream of the first modified commit will receive a new SHA-1 hash.
> 2. **Pull Conflicts for Existing Clones:** Anyone who has previously cloned `https://github.com/midhunkrishnan-131/myx-ai-windows.git` will receive a non-fast-forward rejection on their next `git pull`. They must re-clone the repository or run:
>    ```bash
>    git fetch origin
>    git reset --hard origin/main
>    ```
> 3. **Forks:** Any external GitHub forks must manually sync or rebase against the new upstream `main`.

### Remote Overwrite Command (Requires User Approval):
When you are ready to publish the clean history:
```powershell
# Re-add remote origin if filter-repo reset remotes
git remote add origin https://github.com/midhunkrishnan-131/myx-ai-windows.git

# Force-push the rewritten main branch
git push origin main --force
```

---

## 6. Cleanup Acceptance Criteria Checklist

- [x] External `.bundle` backup verified and intact.
- [x] Staged `.gitignore` configured to block runtime directories and database extensions.
- [ ] User approval received for running history rewrite.
- [ ] `git-filter-repo` executed.
- [ ] Post-rewrite Git history search confirms zero occurrences of sensitive files.
- [ ] Remote `origin/main` force-pushed with clean history.
