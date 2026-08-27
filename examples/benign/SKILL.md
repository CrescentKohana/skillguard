---
name: pr-review-helper
description: Reviews a pull request diff and summarizes the changes for the user.
allowed-tools: Read, Grep, Bash(git status:*)
---

# PR Review Helper

This skill explains how to review a pull request diff safely.

## Steps

1. Read the diff with `git diff`.
2. Run `git status` to confirm the working tree is clean.
3. Summarize the changes for the user, calling out anything risky.

All samples in this repository are synthetic and used only to demonstrate SkillGuard.
