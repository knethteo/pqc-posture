---
name: "PQC Posture"
author: "knethteo"
github_url: "https://github.com/knethteo/pqc-posture"
description: "Post-Quantum Cryptography readiness dashboard for Tenable Vulnerability Management"
license: "MIT"
type: "tool"
tier: "unreviewed"
tags: ["pqc", "post-quantum", "cryptography", "vulnerability-management", "dashboard", "tenable"]
framework: "FastAPI"
integrations: ["Tenable"]
date_added: 2026-06-22
---

PQC Posture is a web-based dashboard that gives security teams visibility into Post-Quantum Cryptography readiness across their asset fleet, powered by Tenable Vulnerability Management data.

## What it does

- Provides a fleet-level overview of assets with PQC-related vulnerability findings
- Drills down into per-asset detail showing specific PQC plugin hits
- Surfaces truncated plugin outputs with direct links to the Tenable console
- Supports both local `.env` configuration and an in-app API key setup page

## How it works

PQC Posture queries the Tenable Workbench API using a configurable set of PQC plugin IDs. Results are cached in memory for 10 minutes and served via a FastAPI backend. The tool can be run locally with `uvicorn` or packaged as a Docker container.
