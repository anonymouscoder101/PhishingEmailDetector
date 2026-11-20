# Phishing Email Detector

A local command-line tool that inspects one RFC 822 `.eml` file for explainable header and URL signals. It reports a rules-based triage score with evidence in text or JSON.

## Requirements

- Python 3.11 or later
- [`uv`](https://docs.astral.sh/uv/)

## Install

From the repository root:

```sh
uv sync
```

## Use

Print a readable report:

```sh
uv run phishdetector suspicious.eml
```

Print the versioned JSON report:

```sh
uv run phishdetector --json suspicious.eml
```

The command accepts one `.eml` file up to 10 MiB. Stdin is not supported. Input and processing errors are written to stderr and return a nonzero exit status. A high score does not make analysis an execution error; completed analyses return zero.

## What it checks

The current rules look for a From/Reply-To domain mismatch, SPF/DKIM/DMARC failures reported in `Authentication-Results`, IP-literal and user-info URL hosts, punycode or non-ASCII host labels, hosts with many subdomains, known URL shorteners, and visible link text whose host differs from its destination. Each finding includes a stable rule ID and evidence.

The score adds rule weights and is clamped to 0–100. The score bands are low (0–24), guarded (25–49), high (50–74), and critical (75–100). These are initial heuristics, not calibrated probabilities or measured accuracy.

## Safety and limitations

- A low score does **not** establish that a message is safe, and a finding does not prove that a message is phishing.
- The tool does not fetch URLs, resolve DNS, follow redirects, render HTML, execute email content, or open/process attachments.
- Only plain-text and HTML bodies are inspected for URLs. Attachments and other MIME parts are skipped.
- `Authentication-Results` is untrusted message content; the tool reports what the header says and cannot establish that a trusted mail server added it.
- Rules can produce false positives and miss phishing messages. The included synthetic fixtures are behavior checks, not a representative labeled evaluation set; they do not establish detection accuracy.
- The input limit is 10 MiB, URL extraction is capped, and displayed terminal evidence is escaped and truncated.

See [the architecture](docs/architecture.md) and [implementation plan](docs/implementation_plan.md) for design details and known scope boundaries.
