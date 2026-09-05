# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the latest minor version of
django-oidc-provider. Older versions may not receive fixes.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| older   | :x:                 |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use one of the following private channels:

1. **GitHub Private Vulnerability Reporting (preferred):**
   Go to the [Security tab](../../security/advisories/new) of this repository
   and click "Report a vulnerability" to open a private advisory.

2. **Email:** If you're unable to use GitHub's private reporting, contact the
   maintainer directly at `juanifioren@gmail.com` with details of the issue.

Please include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested mitigation, if known

## What to Expect

- We will acknowledge receipt of your report within a few business days.
- We will investigate and aim to provide an initial assessment (confirmed,
  needs more info, not a vulnerability) as soon as possible.
- Once a fix is ready, we will coordinate a release and disclosure timeline
  with you. We ask that you give us a reasonable window to patch before any
  public disclosure.
- Credit will be given to reporters in the release notes/changelog, unless
  you prefer to remain anonymous.

## Scope

This policy covers the `django-oidc-provider` package itself. Vulnerabilities
in dependencies (e.g. Django itself) should be reported to their respective
maintainers.
