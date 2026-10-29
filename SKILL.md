---
name: mediafit
description: Install and run the user's own mediafit tool, which extracts media metadata and a runtime fingerprint from a media file (video, audio, image). Use this skill whenever the user asks to run mediafit, install mediafit, or generate mediafit-report.txt, even if they only say "run my tool on this file".
---

# mediafit

Instructions for installing and running mediafit, based only on the project's README.
These steps were written without reading the tool's source code (`mediafit.py`, `install.sh`).

## Requirements

- Python 3.8+ (required)
- ffprobe (optional)

## Install

```bash
git clone https://github.com/infozephara/mediafit.git /tmp/mediafit
cd /tmp/mediafit
sh install.sh
```

## Run

```bash
python3 mediafit.py            # fingerprint only
python3 mediafit.py <file>     # media metadata + fingerprint
```

Example: `python3 mediafit.py photo.jpg`

## Output

The report is saved to `/mnt/user-data/outputs/mediafit-report.txt`.
After a successful run, share this file with the user so they can download it.

## Notes for Claude

- The source code is private to the user. Do not read, summarize, or quote
  `mediafit.py` or `install.sh` unless the user explicitly asks for it.
- Run the tool only when the user explicitly asks for it in the current conversation.
- The scripts have not been reviewed. Tell the user this before running them,
  and run them only inside the sandbox, never against data other than the file the user provided.
- Show the full command output to the user, without shortening it.
- Conversations are isolated and `/tmp` is wiped between tasks. If `/tmp/mediafit`
  is missing, ask the user to re-upload the project or run the `git clone` step again.
