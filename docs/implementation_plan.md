# Phishing Email Detector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a local Python CLI that inspects one `.eml` file, extracts header and URL signals, and reports an explainable heuristic risk score as text or JSON.

**Architecture:** Use Python's standard `email` package for parsing, independent extraction and rule modules, a stable report model, and a weighted 0–100 score. Person A owns parsing and extraction; Person B owns findings, scoring, report formatting, and CLI; both agree on shared models first and integrate together.

**Tech Stack:** Python 3.11+, `uv` for project and environment management, standard library at runtime, `pytest` for development validation, no network or ML dependency in the MVP.

**Spec:** `docs/architecture.md`

## Global Constraints

- Accept one RFC 822 `.eml` file; support stdin only if both partners retain it in scope at kickoff.
- Default maximum input size is 10 MiB.
- Use `uv` to manage the project, lockfile, and virtual environment at `.venv/`; do not install project dependencies globally.
- Commit `uv.lock` so both partners use the same resolved development dependencies; do not commit `.venv/`.
- Do not fetch URLs, resolve redirects, render HTML, execute content, or process attachments.
- Missing `Authentication-Results` means unknown, not failure; those headers are untrusted input.
- Scores are heuristic triage values, not probabilities; bands are 0–24 low, 25–49 guarded, 50–74 high, and 75–100 critical.
- Keep raw email bodies out of logs and errors; escape and truncate attacker-controlled terminal evidence.
- JSON output uses `schema_version: "1"`; a suspicious score is not a CLI execution error.

## Review Focus

- Malformed MIME and unsupported charsets must produce a report or bounded parse warning, not crash. Pin in Person A's parser tests.
- Repeated headers and missing fields must be preserved or represented explicitly. Pin in Person A's header normalization tests.
- HTML links and visible link labels must be extracted without rendering HTML or fetching destinations. Pin in Person A's URL extraction tests.
- Untrusted authentication headers, terminal control characters, and long URLs must not cause unsafe output or false certainty. Pin in Person B's rule and reporting tests.
- Oversized/unreadable inputs must fail with concise errors and no body dump. Pin in the CLI integration tests.

---

## File Map

| File | Owner | Responsibility |
|---|---|---|
| `pyproject.toml` | Person B | Project metadata, Python floor, CLI entry point, dev dependency group |
| `uv.lock` | Both | Lock resolved project and development dependencies |
| `.gitignore` | Person B | Exclude `.venv/`, Python bytecode, and test/lint caches |
| `src/phishdetector/__init__.py` | Person B | Package version/export surface |
| `src/phishdetector/models.py` | Joint contract; Person B implements | Normalized email, URL, finding, and report dataclasses |
| `src/phishdetector/parser.py` | Person A | Input size checks, MIME/header parsing and normalization |
| `src/phishdetector/extractors.py` | Person A | URL extraction and URL-derived facts |
| `src/phishdetector/rules.py` | Person B | Individual deterministic signal rules |
| `src/phishdetector/scoring.py` | Person B | Weight aggregation and severity bands |
| `src/phishdetector/reporting.py` | Person B | Safe text and versioned JSON formatting |
| `src/phishdetector/cli.py` | Joint integration; Person B leads | Argument parsing, orchestration, exit codes, errors |
| `tests/fixtures/` | Person A | Synthetic or sanitized `.eml` samples |
| `tests/test_parser.py` | Person A | Parser and MIME behavior |
| `tests/test_extractors.py` | Person A | URL extraction behavior |
| `tests/test_rules.py` | Person B | Finding IDs, evidence, and weights |
| `tests/test_scoring.py` | Person B | Score caps and severity boundaries |
| `tests/test_reporting.py` | Person B | Stable JSON and safe text rendering |
| `tests/test_cli.py` | Joint | End-to-end file, stdin (if retained), and error behavior |

## Shared Interface Contract (agree before parallel work)

Use dataclasses in `models.py` with these fields; keep parsing and presentation independent.

- `ParsedEmail`: `headers: dict[str, list[str]]`, `text_parts: list[str]`, `html_parts: list[str]`, `parse_warnings: list[str]`.
- `ExtractedUrl`: `original: str`, `normalized: str`, `host: str | None`, `source: str`, `visible_text: str | None = None`.
- `Finding`: `id: str`, `severity: str`, `weight: int`, `message: str`, `evidence: dict[str, str]`.
- `AnalysisReport`: `schema_version: str`, `score: int`, `severity: str`, `findings: list[Finding]`, `urls: list[str]`, `parse_warnings: list[str]`.

Functions shared across modules:

- `parse_email(data: bytes, max_bytes: int = 10 * 1024 * 1024) -> ParsedEmail`
- `extract_urls(email: ParsedEmail) -> list[ExtractedUrl]`
- `evaluate_rules(email: ParsedEmail, urls: list[ExtractedUrl]) -> list[Finding]`
- `calculate_score(findings: list[Finding]) -> tuple[int, str]`
- `build_report(email: ParsedEmail, urls: list[ExtractedUrl], findings: list[Finding]) -> AnalysisReport`
- `render_text(report: AnalysisReport) -> str`
- `render_json(report: AnalysisReport) -> str`

Decisions agreed at kickoff:

- Person A writes `models.py`; Person B reviews it.
- Stdin is out of scope for the MVP; the CLI accepts one file path.
- `ParsedEmail.headers` keys are lowercase (for example `headers["reply-to"]`); values are decoded and kept in file order.
- Rules derive From/Reply-To domains in `rules.py` with `email.utils.getaddresses`; the parser supplies the header values only.
- `parse_email` raises only `InputTooLargeError` (in `models.py`) for oversized input; malformed content is reported through `parse_warnings`.

Notes from Person A's implementation (Phase 2A) that affect rules and reporting:

- `ExtractedUrl.source` is one of `"text"` (plain-text body), `"html_href"` (an `<a href>`), or `"html_text"` (a URL written in HTML text outside a link).
- `ExtractedUrl.original` is kept exactly as found and can contain terminal control characters from an `href`; reporting must escape it.
- `ExtractedUrl.host` is lowercase, without port or user-info, and never converted to `xn--` form; the punycode rule should check for `xn--` labels and non-ASCII characters. It is `None` when the URL cannot be parsed or the host contains whitespace or control characters.
- Backslashes are treated as slashes when deriving `host`, as browsers do, so `http://evil.test\@good.example.com` reports `evil.test`.
- `ExtractedUrl.visible_text` is the whitespace-collapsed link label for `html_href` URLs, or `None` when there is no label (for example, an image-only link).
- `extract_urls` appends a warning to `email.parse_warnings` when it reaches the 500-URL limit or cannot fully parse an HTML part; call `build_report` after `extract_urls` so these warnings appear.

Agree on names and fields in a short kickoff before implementation. If a field must change, update this contract and both owners' tests in the same change.

## Partner Work Plan

### Phase 1: Joint kickoff and repository setup

**Pair:** Both partners. **Driver:** Person B; Person A reviews the shared contract.

- [ ] Confirm the interface contract above, including whether stdin is in the MVP.
- [ ] Confirm both partners have `uv` installed, then initialize the project with `uv init --package --python 3.11` (or configure the equivalent fields in `pyproject.toml` if the scaffold is created manually).
- [ ] Add `.venv/`, `__pycache__/`, `*.py[cod]`, and `.pytest_cache/` to the root `.gitignore` before committing project files.
- [ ] Create the package and test directory layout from the file map; retain `uv`'s generated `pyproject.toml` and `.python-version` where applicable.
- [ ] Configure the project with `requires-python = ">=3.11"`, a `phishdetector` console script targeting `phishdetector.cli:main`, and the `dev` dependency group.
- [ ] Add `pytest` with `uv add --dev pytest`, then run `uv sync` to create `.venv/` and `uv.lock`; commit the lockfile.
- [ ] Add a minimal import/CLI smoke test and verify it runs through `uv run` in the managed project environment.
- [ ] Commit the scaffold before splitting work.

**Handoff:** Both partners use the same dataclasses and function signatures; no parallel changes to `models.py` after sign-off without coordination.

### Phase 2A: Parse email and extract URLs

**Owner:** Person A.

**Files:** `parser.py`, `extractors.py`, `tests/fixtures/`, `tests/test_parser.py`, `tests/test_extractors.py`.

- [x] Add parser tests for a simple message, multipart text/HTML, repeated headers, missing headers, malformed MIME, charset decoding fallback, and an input larger than 10 MiB.
- [x] Implement `parse_email(data, max_bytes=...)` using `email.parser.BytesParser` with a modern email policy; preserve repeated header values and capture parser defects as warnings.
- [x] Decode only `text/plain` and `text/html` bodies; skip attachments and non-text parts. Handle decode failures without raising.
- [x] Add URL extraction tests for plain text, HTML `href` values, visible link text, duplicate links, malformed URLs, and strings containing terminal control characters.
- [x] Implement `extract_urls(email)` without DNS or HTTP access. Retain the original value for evidence; use safe parsing to derive normalized URL and hostname.
- [x] Run `uv run pytest tests/test_parser.py tests/test_extractors.py -q` and resolve failures.
- [x] Commit with a focused message such as `feat: parse email and extract urls`.

**Produces:** `ParsedEmail`, `ExtractedUrl`, `parse_email`, and `extract_urls` as defined in the shared contract.

### Phase 2B: Rules, scoring, and reporting

**Owner:** Person B. Can proceed alongside Phase 2A after the contract is agreed.

**Files:** `models.py`, `rules.py`, `scoring.py`, `reporting.py`, `tests/test_rules.py`, `tests/test_scoring.py`, `tests/test_reporting.py`.

- [x] Add rule tests for From/Reply-To domain mismatch; reported SPF/DKIM/DMARC failure; missing authentication result treated as unknown; URL IP host, user-info, punycode, excessive subdomains, shortener, and visible-text/destination mismatch.
- [x] Implement `evaluate_rules(email, urls)` with stable finding IDs, bounded evidence, and documented integer weights. Keep content phrases weak and optional; do not let keywords alone produce a high score.
- [x] Add scoring tests for empty findings, additive weights, 100-point cap, and exact band boundaries (24/25, 49/50, 74/75).
- [x] Implement `calculate_score(findings)` as positive weight sum clamped to 100, mapped to the four defined bands.
- [x] Add report tests asserting schema version, stable JSON fields, and escaped/truncated text evidence.
- [x] Implement `build_report`, `render_text`, and `render_json`; label the result heuristic and not a probability.
- [x] Run `uv run pytest tests/test_rules.py tests/test_scoring.py tests/test_reporting.py -q` and resolve failures.
- [x] Commit with a focused message such as `feat: add explainable risk scoring`.

**Produces:** Rules, scoring, report construction, and renderers matching the shared contract.

### Phase 3: CLI integration

**Owner:** Person B leads; Person A reviews file-input behavior.

**Files:** `cli.py`, `tests/test_cli.py`.

- [ ] Add CLI tests for `.eml` path input, `--json`, unreadable path, invalid arguments, oversized input, and stdin if retained in Phase 1.
- [ ] Implement `main(argv: list[str] | None = None) -> int` to read bytes, call the parser/extractor/rules/scorer/reporting pipeline, and select text or JSON output.
- [ ] Send concise operational errors to stderr; return nonzero only for input/processing errors. Return zero when analysis completes, regardless of score.
- [ ] Ensure raw message bodies are never included in logs or CLI errors.
- [ ] Run `uv run pytest tests/test_cli.py -q` and manually inspect one benign and one suspicious fixture in both output formats.
- [ ] Commit with `feat: add phishing email detector cli`.

### Phase 4: Joint integration review

**Pair:** Both partners.

- [ ] Run the full suite with `uv run pytest -q`.
- [ ] Review fixtures together and verify each expected finding maps to a rule ID and sensible evidence.
- [ ] Review terminal output for control-character safety and JSON for schema stability.
- [ ] Confirm there are no network calls, attachment handling, body logging, or unsupported safety claims.
- [ ] Update README usage examples and limitations, including that a low score does not establish safety.
- [ ] Record false positives, false negatives, and weight changes in a short changelog or review note; do not claim classifier accuracy from the small fixture set.
- [ ] Create a final integration commit after both partners approve the report behavior.

### Phase 5: Optional machine-learning extension (after the MVP)

**Status:** Deferred until the rules-based MVP works. This phase is optional, requires a suitable labeled dataset, and is not part of MVP completion. If no dataset meets the gate below, stop after documenting that decision; do not train on examples invented solely to make a model run.

**Goal:** Test whether a small scikit-learn classifier using non-sensitive indicators adds measurable value over the existing rules-only scorer. Keep the rules score available and report the model assessment separately.

**Owners:** Person A owns dataset review, feature extraction, and data documentation. Person B owns the scikit-learn pipeline, training/evaluation script, and optional CLI integration. Both partners approve the dataset gate, evaluation results, and any user-facing model output.

**Files (only if this phase is approved):**

- `data/ml/README.md` — provenance, permitted use, labels, exclusions, and reproducible preparation instructions; do not commit raw emails.
- `src/phishdetector/ml_features.py` — convert normalized email and extracted URLs to the fixed feature mapping below.
- `src/phishdetector/ml_model.py` — train/evaluate helpers and trusted local model loading.
- `scripts/evaluate_model.py` — deterministic split, rules baseline, ML baseline, and metrics output.
- `tests/test_ml_features.py` and `tests/test_ml_model.py` — feature stability, training, loading, and optional-dependency behavior.
- `pyproject.toml` and `uv.lock` — optional `ml` dependency group only; do not add scikit-learn to the default runtime dependencies.
- `src/phishdetector/models.py`, `reporting.py`, `cli.py` — only if both partners approve the optional report fields and `--ml` interface after evaluation.

### Dataset readiness gate — Person A, reviewed by Person B

- [ ] Identify a legally usable dataset with message-level labels `phishing` or `benign`, documented source, collection period, labeling method, and known limitations.
- [ ] Keep raw messages outside the repository. Remove or avoid retaining addresses, names, message IDs, and body text in the derived dataset. Store only row ID, label, campaign/source grouping key, and approved derived features where possible.
- [ ] Check duplicates and near-duplicates, class balance, mislabeled or ambiguous samples, and whether the dataset reflects the intended use. Record counts and exclusions in `data/ml/README.md`.
- [ ] Confirm that each class and campaign/source group has enough examples for a meaningful held-out evaluation. If the dataset is too small or too biased to support that, stop Phase 5 and document the reason; do not report model performance as evidence of effectiveness.
- [ ] Add dataset files and any derived private data paths to `.gitignore`; commit only the documentation and scripts, not the emails or private feature table.

**Gate result:** Both partners sign off in a short note on provenance, privacy, label quality, and evaluation feasibility before adding scikit-learn.

### Feature and dependency implementation — Person A

- [ ] Add `ml_features.py` with `extract_ml_features(email: ParsedEmail, urls: list[ExtractedUrl]) -> dict[str, int | float]`.
- [ ] Use only aggregated indicators already available from parsing and extraction: URL count; count of IP-literal, punycode, user-info, shortener, and excessive-subdomain URLs; From/Reply-To domain-match flag; SPF/DKIM/DMARC result categories; parse-defect count; and a small count of approved urgency/credential phrases.
- [ ] Do not include raw addresses, full URLs, domains, message body text, filenames, or authentication-header strings as model features. Define behavior for missing values and cap count features at documented limits.
- [ ] Add feature tests for deterministic output, missing headers, malformed URLs, repeated headers, empty bodies, and capped counts.
- [ ] After the dataset gate passes, add scikit-learn only to the optional `ml` dependency group using `uv add --group ml scikit-learn`; update `uv.lock`. The rules-only path must work without installing this group.

### Training and evaluation — Person B

- [ ] Add `scripts/evaluate_model.py` to load an approved derived dataset, verify required columns and labels, and stop with a clear error for invalid input.
- [ ] Split by campaign/source grouping so related messages cannot appear in both train and evaluation data; use a fixed random seed and stratify labels where the grouping allows it. Never select features or tune thresholds using the held-out set.
- [ ] Compare three results on the same held-out examples: majority-class baseline, current rules-only classification at a documented threshold, and scikit-learn `DummyClassifier` plus a simple `LogisticRegression` pipeline. Fit preprocessing only on training data.
- [ ] Report class counts, precision, recall, F1, confusion matrix, and precision-recall AUC where both classes are present. Include the threshold and split method. Do not describe metrics from a small or unrepresentative dataset as general phishing-detection accuracy.
- [ ] Keep training reproducible with a pinned random seed and save a metrics report. Do not commit raw data or a model artifact unless both partners approve its provenance and storage.
- [ ] If saving a model artifact, load only the locally generated, reviewed artifact. Never load model files supplied by users or downloaded from an untrusted source.
- [ ] Add tests for invalid labels/schema, deterministic split setup, missing features, training output shape, and clear behavior when scikit-learn is not installed.
- [ ] Run `uv run --group ml python scripts/evaluate_model.py --data <approved-derived-data-path>` and `uv run --group ml pytest tests/test_ml_features.py tests/test_ml_model.py -q`; record the actual results and limitations.

### Optional CLI/report integration — both partners decide after evaluation

- [ ] Integrate only if the held-out results show a useful, explainable improvement over the baselines and both partners agree the data supports that conclusion.
- [ ] Add an opt-in `--ml` flag; default CLI operation remains rules-only and does not require scikit-learn. If the user requests `--ml` without the optional dependency, return a concise install/use hint.
- [ ] Add an optional `ml_assessment` object to JSON only after defining and documenting its fields. Preserve schema version `"1"` for rules-only output; increment the schema version if the JSON shape changes incompatibly.
- [ ] Display model label and any score separately from the heuristic rules score. Do not combine them or label `predict_proba` as a calibrated risk probability unless a separate calibration step is evaluated on data not used for fitting or threshold selection.
- [ ] Add CLI/report tests for rules-only output, `--ml` with the extra installed, `--ml` without the extra, and stable JSON version behavior.
- [ ] Document retraining steps, dataset version/provenance, model version, held-out results, and known limitations. Keep ML disabled by default unless future evidence and project requirements justify changing that behavior.

## Definition of Done

- `phishdetector sample.eml` emits a readable score, severity, findings, extracted URLs, and parse warnings.
- `phishdetector --json sample.eml` emits valid JSON with `schema_version` set to `"1"`.
- Malformed but bounded email input does not crash; unreadable and oversized input reports a concise error.
- The score is deterministic for the same input and rules, bounded to 0–100, and accompanied by evidence.
- No links are fetched and no attachment is opened or executed.
- Both partners have reviewed the shared contract, CLI report, known limitations, and fixture outcomes.
- Machine learning is not part of MVP completion; the optional Phase 5 requires a separate dataset and evaluation review.

## Assumptions and Deferred Choices

- This is a proposed implementation plan based on `docs/architecture.md`, not an approval that all heuristic weights are empirically calibrated.
- Use `uv` with `pyproject.toml` and commit `uv.lock` for reproducible dependency resolution.
- Let `uv sync` create and maintain `.venv/`; use `uv run <command>` so commands run in the project environment without requiring shell activation.
- Add development dependencies with `uv add --dev <package>`; do not use `pip install` for project dependencies.
- Keep the runtime dependency-free; use `pytest` only for development.
- Use synthetic or sanitized fixtures with no real personal email data.
- Defer scikit-learn until the team has a documented, representative, labeled dataset and evaluation plan.
- Phase 5 is a future option and may be omitted if the project schedule or dataset does not support responsible evaluation.
