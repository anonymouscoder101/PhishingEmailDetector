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

---

# Phase 4 Integration Review — Person A

**Review date:** 2026-11-20  
**Scope:** Person A's review of fixtures, extraction-to-rules integration, and safety boundaries. Prepared with AI assistance (Claude) and checked by running the tool.

## Suspicious fixture added

`tests/fixtures/suspicious.eml` is a synthetic phishing-style message (only `.test` domains, a documentation IP, and one shortener domain). It is designed to trigger every current rule once:

| Signal in the fixture | Rule triggered | Evidence |
|---|---|---|
| Reply-To on a different domain | `header.reply_to_mismatch` | `example-bank.test` vs `collector.test` |
| `spf=fail`, `dkim=fail`, `dmarc=fail` | `auth.spf_fail`, `auth.dkim_fail`, `auth.dmarc_fail` | mechanism and reported result |
| Link to `http://192.0.2.10/verify` | `url.ip_literal` | `192.0.2.10` |
| That link's text shows `https://www.example-bank.test/verify` | `url.visible_text_mismatch` | visible vs destination host |
| `https://www.example-bank.test@login.collector.test/` | `url.userinfo` | full URL; host correctly reported as `login.collector.test` |
| `xn--` host | `url.punycode` | host |
| `secure.login.account.verify.collector.test` | `url.excessive_subdomains` | 4 subdomain labels |
| `bit.ly` link | `url.shortener` | `bit.ly` |

Result: score 100 (critical), exit code 0, no parse warnings. Every finding maps to a rule ID with sensible evidence.

`tests/test_fixtures.py` pins the rule IDs each fixture triggers (as sets, so weight changes do not break it), checks the suspicious fixture's evidence, and confirms every fixture renders valid schema-version-1 JSON. Full suite: 106 passed.

## Safety confirmation

- Source contains no HTTP, DNS, socket, subprocess, or logging use. The only output besides the report is three fixed stderr messages in `cli.py`.
- The parser never decodes attachments and never descends into attachment parts; nesting depth, part count, URL count, and warning count are bounded.
- Parse warnings are fixed strings and never contain message content.

## Issues found for discussion (Person B's files)

1. **Duplicate findings inflate the score.** A link that appears in both the plain-text and HTML versions of an email (normal for real mail) is scored twice, because extraction keeps one entry per source as agreed. One IP-literal link scores 50 (high) instead of 25; the same link four times scores 100. Visible in `suspicious.eml`, where `url.ip_literal` appears twice. Suggested fix: in `evaluate_rules`, keep only one finding per (rule ID, evidence).
2. **Visible-text mismatch false positives.** Any link label containing a dot is treated as a host: a label `invoice.pdf` is flagged, and so is a label `example.com` linking to `www.example.com` (+20 each). Suggested fix: only compare labels that look like URLs or domains, and treat a `www.` prefix as equivalent.
3. **JSON passes some invisible control characters through.** `render_json` uses `ensure_ascii=False`, so C1 controls such as `\x9b` and bidi overrides such as U+202E from an `href` appear unescaped in `urls`. Suggested fix: `ensure_ascii=True`.
4. **Minor:** only `fail` is flagged for SPF/DKIM/DMARC; `softfail`, `permerror`, and `temperror` are not. Possibly intentional; worth deciding explicitly.

Person A approves the parse and extraction side of the report behavior. Final approval is pending agreement on items 1–3.
