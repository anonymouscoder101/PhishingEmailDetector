# Phase 4 Integration Review — Person B

**Review date:** 2026-11-19  
**Scope:** Person B's review of the current fixtures, report behavior, and MVP safety constraints. This records implementation evidence; it is not the joint partner sign-off.

## Fixture outcomes

| Fixture | Observed result | Review |
|---|---|---|
| `simple.eml` | Score 0 (low), one cafe URL, no findings or warnings | Expected benign behavior for this rule set. |
| `missing_headers.eml` | Score 0 (low), no URLs, findings, or warnings | Missing optional headers are tolerated. |
| `malformed_mime.eml` | Score 0 (low), no findings, two MIME defect warnings | Malformed MIME is reported without a crash or raw body output. |
| `multipart.eml` | Score 0 (low), invoice URL retained from plain text and HTML sources | The same destination is listed twice because the extractor preserves source distinctions. Attachment content and its URL are skipped. |
| `repeated_headers.eml` | Score 10 (low), one `auth.dkim_fail` finding | The explicit reported failure is surfaced as untrusted header evidence; SPF pass and absent DMARC result do not create findings. |

The unit tests also cover mismatch and suspicious URL rules, score boundaries, JSON schema order, terminal-control escaping, and bounded evidence.

## False positives, false negatives, and weights

The fixtures are synthetic behavior examples and do not have message-level phishing/benign truth labels. False-positive and false-negative rates therefore cannot be calculated from them. These outcomes are not accuracy evidence. No weights were changed during this review; the current weights remain initial, uncalibrated triage heuristics.

## Safety and output review

- The production source contains no HTTP, DNS, or socket client use. URL inspection uses string parsing only.
- Parser tests verify that attachments are skipped; the CLI reads only the selected `.eml` file.
- CLI input is read to at most 10 MiB plus one byte before rejection. Its error messages do not include message contents; tests check that an oversized body's sentinel is absent from stderr.
- Text reporting escapes terminal control characters and truncates output values. JSON uses the standard JSON encoder and keeps schema version `"1"`.
- Reports state that the score is heuristic and that a low score does not establish safety. Authentication results are explicitly described as untrusted.

## Verification

- Full suite: `uv run pytest -q` — 91 passed.
- Manually inspected benign and suspicious fixture output in text and JSON formats. A suspicious result still exits zero when analysis completes.

## Remaining joint work

Person A and Person B still need to review these outcomes together and approve report behavior. The final integration commit remains pending that joint approval.
