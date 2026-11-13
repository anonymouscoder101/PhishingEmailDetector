# Phishing Email Detector — Architecture

**Status:** Proposed MVP design  
**Audience:** Two-person project team  
**Date:** 2026-11-12

## 1. Purpose

Build a small Python tool that inspects a suspicious email, surfaces header and URL indicators, and returns a risk score with reasons a person can review. It is a triage aid, not a mail gateway or a guarantee that an email is safe.

The first release is a local command-line application that accepts an RFC 822 `.eml` file and prints a human-readable report (with optional JSON output). Processing stays on the user's machine; the tool does not send email contents to a service.

## 2. Goals and boundaries

### Goals

- Parse common email headers and tolerate malformed or incomplete messages.
- Extract URLs from plain-text and HTML MIME parts without fetching them.
- Identify explainable signals such as sender/reply-to mismatch, failed or absent authentication results, suspicious URL forms, and header inconsistencies.
- Produce a bounded 0–100 risk score, a severity label, and the evidence behind each finding.
- Keep parsing, signal detection, scoring, and output independently testable.

### Non-goals for the MVP

- Blocking, quarantining, forwarding, or sending email.
- Clicking links, resolving redirects, querying reputation services, or executing attachments.
- Building a web interface, mail-server integration, or real-time classifier.
- Claiming definitive phishing detection. A low score is not a safety guarantee.
- Training or shipping a machine-learning model before a suitable labeled dataset exists.

## 3. Approaches considered

1. **Rules-only scorer (recommended for the MVP).** A deterministic set of weighted signals is quick to implement, works without a training corpus, and makes each result explainable. Its coverage depends on the quality of the rules and it may miss novel attacks.
2. **Machine-learning-first scorer.** A scikit-learn classifier can combine signals, but needs representative labeled examples, careful evaluation, and model versioning. Without those, reported confidence would be misleading.
3. **Hybrid scorer.** Keep deterministic signals as the stable baseline and add a separately reported model result when a validated model and dataset exist. This offers a path to improve coverage without losing explanations, but adds operational and evaluation work.

The MVP uses approach 1, with component boundaries that allow approach 3 later. The request names regex or scikit-learn; choosing rules first is a project assumption based on the absence of a specified dataset and the two-person scope.

## 4. System shape

```text
 .eml file / stdin
       |
       v
 CLI and input validation
       |
       v
 Email parser (Python email package)
       |
       +--> normalized headers
       +--> decoded text / HTML MIME parts
                    |
                    v
       URL and indicator extraction
                    |
                    v
       Signal rules --> weighted scorer
                    |
                    v
         report model --> text or JSON
```

### Modules

- **`cli`** — arguments, input selection, output format, exit status, and user-facing errors. It does not contain detection rules.
- **`parser`** — reads bytes and uses Python's standard-library `email` package to parse headers and MIME parts. It returns a normalized internal message object; it never follows links or opens attachments.
- **`extractors`** — extracts URLs from text and HTML, normalizes safe-to-inspect URL fields, and derives header facts. Preserve the original URL string for display. Do not fetch or resolve it.
- **`rules`** — evaluates independent checks and emits findings with stable IDs, descriptions, evidence, and weights.
- **`scoring`** — aggregates findings into a clamped 0–100 score and maps it to a severity band. Rules do not directly format output.
- **`reporting`** — serializes the same report model to readable text or JSON.

Suggested package layout:

```text
src/phishdetector/
  cli.py
  parser.py
  models.py
  extractors.py
  rules.py
  scoring.py
  reporting.py
```

## 5. Processing and scoring

1. Read one `.eml` input as bytes. Reject an unreadable file, and impose a configurable size limit (initial default: 10 MiB) to avoid unbounded input processing.
2. Parse with the standard library, preserving repeated headers and recording parse defects where available. Missing fields should become absent values, not fatal errors.
3. Decode supported text and HTML MIME parts with declared charset and safe fallback behavior. Ignore attachments in the MVP; never execute or unpack them.
4. Extract URLs from both body forms. Deduplicate for analysis while preserving source locations and original spellings for evidence.
5. Evaluate rules independently. Each finding includes an ID, title, explanation, severity, weight, and evidence (for example, the relevant header name or a redacted URL).
6. Sum positive weights, cap the score at 100, and map it to bands: 0–24 low, 25–49 guarded, 50–74 high, 75–100 critical. These thresholds and weights are initial heuristics and must be tuned against examples; they are not probabilities.
7. Render the report. Default output is text; `--json` emits a stable machine-readable representation.

Initial rule families:

- **Header consistency:** From/Reply-To domain mismatch; display-name/domain mismatch where safely derivable; multiple or malformed routing/authentication headers as review signals.
- **Authentication:** SPF, DKIM, and DMARC results as reported in `Authentication-Results`. Treat absent results as unknown, not automatically as failure. These headers are untrusted input and can be forged outside a trusted receiving system.
- **URL structure:** IP-literal hosts, user-info before the host, punycode labels, excessive subdomains, mismatched visible link text and destination host, and URL shorteners based on a small configurable list.
- **Message content:** A limited set of urgency or credential/payment phrases can be considered only as weak signals; avoid assigning a high score based on keywords alone.

Each rule should have a stable ID and unit examples. Evidence shown to users should be escaped in terminal output and truncated to avoid terminal control sequences or unwieldy URLs.

## 6. Data model and interface

The core report is independent of CLI formatting:

```json
{
  "schema_version": "1",
  "score": 62,
  "severity": "high",
  "findings": [
    {
      "id": "header.reply_to_mismatch",
      "severity": "medium",
      "weight": 20,
      "message": "Reply-To domain differs from From domain",
      "evidence": {"from_domain": "example.com", "reply_to_domain": "other.test"}
    }
  ],
  "urls": ["https://other.test/login"],
  "parse_warnings": []
}
```

The score is an ordinal triage value, not a calibrated probability. JSON should be versioned so downstream scripts can detect format changes. Add a CLI exit code for execution errors; a suspicious score should not itself be an execution error.

## 7. Security, privacy, and reliability

- Treat the entire message—including headers, URL strings, filenames, and authentication results—as attacker-controlled.
- Do not make network requests, auto-open links, render HTML, execute content, or process attachments in the MVP.
- Keep input local and do not log raw message bodies by default. Error messages should avoid dumping full email content.
- Set input-size and extraction limits. Handle malformed encodings and MIME structures without crashing.
- Escape terminal output and HTML-derived text. Do not use extracted strings as shell commands or file paths.
- Clearly state in help and reports that results are heuristic and that a low score does not establish safety.

## 8. Validation strategy

Use a small, reviewed collection of benign and suspicious `.eml` fixtures with sensitive details removed or synthetic. Cover malformed messages, multipart text/HTML, repeated headers, absent authentication results, URL edge cases, and expected findings. Track false positives and false negatives by rule; do not claim accuracy from a tiny hand-built set. If a classifier is later considered, reserve held-out data, compare against the rules baseline, report precision/recall and class balance, and document dataset provenance.

## 9. Work split for two people

Work can proceed in parallel after agreeing on the normalized message and finding/report models.

- **Person A — parsing and extraction:** input handling, MIME/header normalization, URL extraction, malformed-input behavior, and parser fixtures.
- **Person B — detection and presentation:** rule definitions, score aggregation, report model/serialization, and CLI presentation.
- **Together:** agree on model fields and rule IDs first, integrate through those interfaces, review findings and examples, and document known limitations.

Keep interfaces small and avoid parallel edits to the same module. A lightweight issue list should separate parser, rule, and integration tasks.

## 10. Delivery sequence and open decisions

1. Agree on report schema, supported input, and rule IDs.
2. Implement `.eml` parsing and URL extraction with fixture examples.
3. Implement the first explainable rules and weighted score.
4. Add text and JSON CLI reports, limits, and clear error handling.
5. Review examples together and adjust weights/thresholds; document observed limitations.

Open decisions for implementation: exact Python version and packaging tool; whether stdin is required in addition to file input; final input-size limit; and the initial source/ownership of sanitized fixtures. Defaults proposed here are Python 3.11+, standard-library parsing, a 10 MiB limit, and local synthetic or sanitized fixtures.
