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

### Resolution of issues 1–3

With Person B's agreement, Person A fixed issues 1–3 on 2026-11-20. Full suite: 118 passed.

| Issue | Fix | Before → after |
|---|---|---|
| 1. Duplicate findings | `evaluate_rules` keeps one finding per (rule ID, evidence). `build_report` lists each distinct URL once. | One IP link in text + HTML: 50 → 25. The same link 4 times: 100 → 25. `suspicious.eml` now shows `url.ip_literal` once and no repeated URLs. |
| 2. Visible-text false positives | Link labels count as hosts only if they start with `http(s)://` or `www.`, or end in an alphabetic top-level label that is not a common file extension. A `www.` prefix matches the bare domain. | `invoice.pdf`: 20 → 0. `example.com` linking to `www.example.com`: 20 → 0. Real mismatches are still flagged. |
| 3. JSON control characters | `render_json` uses `ensure_ascii=True`. | `\x9b` and U+202E now appear escaped (`\u009b`, `‮`); the JSON still decodes to the same values. |

Trade-off for issue 2: `.zip` and `.mov` are real top-level domains, but a label like `invoice.zip` is treated as a file name, not a domain. A label that starts with `www.` or `http` is always compared.

Item 4 (`softfail`, `permerror`, `temperror`) is unchanged and still open for a decision.

## False negatives observed on real spam

Person A ran the tool locally on two real spam messages from a personal junk folder. The messages are not committed, and no personal details or tracking identifiers are recorded here. Both were clearly phishing to a human reader, but both scored **0 (low)** with no findings. Extraction worked as intended in both: every link was found, and nothing crashed.

**Message 1: "reward reservation" email styled as a well-known ISP brand.** What a person notices: brand impersonation, a too-good-to-be-true prize, a same-day deadline, and a single "claim" button. Every link points to `storage.googleapis.com`, with random bucket and file names (`/<random>/<random>/<random>.html`) and junk tracking text after `#`.

| Why no rule fired | Possible rule |
|---|---|
| The links use a legitimate, well-formed host. No rule knows that public cloud storage is commonly abused to host phishing pages. | `url.cloud_hosted_page`: links to commonly abused hosting (`storage.googleapis.com`, `firebasestorage.googleapis.com`, `*.blob.core.windows.net`, `*.s3.amazonaws.com`), especially direct `.html` files. Moderate weight, because legitimate mail also uses these services. |
| The brand impersonation is visible only in the content and display name, which the rules do not inspect. | `header.display_name_mismatch` (already listed in `docs/architecture.md` but not implemented): a brand in the From display name that does not match the sender domain. |
| The scam wording (prize, deadline, "claim") is not checked. | Weak, capped urgency and reward phrases ("claim", "reward", "expires today"), which the plan allows only as weak signals. |

**Message 2: "exclusive survey invitation" email styled as a well-known retail brand.** What a person notices: brand impersonation, "Congratulations!", a "$100+" gift for completing a short survey, and urgency ("Don't put it off!", "complete your survey today"). Every link again points to `storage.googleapis.com`, to a single `.html` file in one bucket, with an encoded tracking value after `#`. No parse warnings.

It was missed for the same three reasons as Message 1, and the same three proposed rules would apply.

**Pattern across both messages:** both use a different brand and a different lure (reward reservation, survey gift), but both host the landing page as a single `.html` file on `storage.googleapis.com` and put per-recipient tracking data after `#`. This makes `url.cloud_hosted_page` the most promising new rule: it targets the shared infrastructure rather than the wording, which changes from campaign to campaign.

Other observations from these runs:

- **The same URL is listed several times in the report.** When several links share one destination but have different visible text, the extractor keeps each one (needed for the visible-text rule), and `build_report` lists every entry. The displayed `urls` list could be deduplicated. This is related to issue 1.
- **"Unknown charset" warnings on Message 1 were caused by a malformed message, not a parser bug.** Both of its body parts declare `charset=3DUTF-8`: the sender's software applied quoted-printable encoding (`=` written as `=3D`) to the header as well as the body, producing a charset name that does not exist. The parser behaved as designed: it reported the problem and fell back to UTF-8, which is what the sender intended. Message 2 declares a valid `UTF-8` and had no warnings. Because legitimate mail systems almost never produce this error, a quoted-printable artifact in MIME headers could be a weak signal of bulk-spam tooling.

Real messages tested so far are not a representative sample and do not support any accuracy claim. They show that the current rule set detects technical indicators (header and URL structure) and does not detect content-based or brand-impersonation scams sent from well-configured infrastructure.

Person A approves the parse and extraction side of the report behavior. Items 1–3 are fixed (see above); final approval is pending Person B's review of those fixes and the joint review.
