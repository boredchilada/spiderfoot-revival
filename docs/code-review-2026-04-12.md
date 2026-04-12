# Code Review — SpiderFoot Revival
**Date**: 2026-04-12
**Scope**: Full codebase audit — event pipeline, security, correlation engine, concurrency, architecture
**Reviewed by**: Claude Code audit (5 parallel review agents)

## Summary

55 findings across the entire codebase: **8 Critical**, **14 High**, **19 Medium**, **14 Low**. The most severe class of bugs is in the event pipeline where the production deduplication architecture is entirely bypassed (storeOnly flag ignored in threaded mode), deepcopy failures crash entire scans, and the default 1024-byte storage truncation silently destroys certificates and DNS records. Security findings include plaintext password storage, API key leakage via config export, CSV injection in exports, and a broken `re.IGNORECASE` call in credential redaction. The correlation engine has an infinite-loop risk with no cycle detection in entity enrichment, and crashes on `None` returns from `collect_from_db()`.

---

## Critical Findings

### [C1] `storeOnly` Deduplication Completely Bypassed in Production (Threaded Mode)
**File**: `spiderfoot/plugin.py:379-382`
**Category**: OSINT Data Integrity
**Issue**: The `storeOnly` suppression flag — designed to prevent re-triggering cascading module chains when duplicate data exists upstream — is only checked in the legacy non-threaded code path. In production (where `outgoingEventQueue` is always set for every module via `sfscan.py:352`), the threaded path at line 382 simply calls `self.outgoingEventQueue.put(sfEvent)` without checking `storeOnly`. This means the entire deduplication architecture described in the code comments ("avoid messy iterations that traverse many many levels") is **completely disabled** in production.
**Why it matters for SpiderFoot**: A domain found multiple times through different chains will re-trigger all downstream modules redundantly — DNS resolvers, co-host lookups, and API modules all receive duplicate work items, producing duplicate events that cascade further. This wastes API quota, inflates scan results, and makes correlation analysis unreliable due to duplicate counts.
**Fix**: Set `sfEvent.storeOnly = storeOnly` before queuing, and filter in `waitForThreads()` to only dispatch to `__stor` modules when `storeOnly is True`.

---

### [C2] `deepcopy()` Has No Exception Handler — One Bad Event Crashes the Entire Scan
**File**: `sfscan.py:524-527`
**Category**: OSINT Data Integrity
**Issue**: `mod.incomingEventQueue.put(deepcopy(sfEvent))` has no try/except. If `deepcopy()` raises `TypeError` or `RecursionError` (non-serializable object, circular reference), the exception propagates to the outer try block whose `finally` sets `_stopScanning = True` on ALL modules and calls `sharedThreadPool.shutdown()`. The entire scan dies with no diagnostic about which event/module caused it.
**Why it matters for SpiderFoot**: The scan appears to have crashed rather than completing. The user has no signal about which data caused the failure. Partial results may be stored but are incomplete with no indication of what was missed.
**Fix**: Wrap in try/except that logs `sfEvent.eventType` and data length, then `continue` to the next module.

---

### [C3] Default `maxstorage=1024` Silently Truncates Certificates, DNS Records, Headers
**File**: `modules/sfp__stor_db.py:28,54-56`; `spiderfoot/db.py:1426-1427`
**Category**: OSINT Data Integrity
**Issue**: The storage module's default `maxstorage` is 1024 bytes. Any event data exceeding this is silently truncated before database storage with no warning logged. PEM certificates are typically 1500-3000 bytes, DNS zone transfers and WHOIS dumps easily exceed 1KB, and CDN HTTP headers regularly exceed 1KB. The truncated data is un-parseable — a half-certificate, partial JSON, or truncated DNS record is worse than no data.
**Why it matters for SpiderFoot**: The stored OSINT data — the primary output of the platform — is silently corrupted. Users reviewing scan results see truncated, un-parseable data without knowing it was truncated.
**Fix**: Change `maxstorage` default from `1024` to `0` (unlimited). If a limit is needed, use 100000.

---

### [C4] `enrich_event_entities()` Has No Cycle Detection or Depth Limit — Infinite Loop Possible
**File**: `spiderfoot/correlation.py:303-336`
**Category**: Correlation Correctness
**Issue**: The while loop traversing parent event chains has no visited set, no depth counter, and no maximum iteration guard. A referential cycle in the event graph (possible with DNS resolve modules producing events sourced by their own consumed events) causes the correlator to hang indefinitely. Even non-cyclic deep chains can cause very long runs.
**Why it matters for SpiderFoot**: The correlation engine — the feature that produces actionable intelligence from raw data — hangs silently. Post-scan analysis never completes. The user sees no correlations and has no indication why.
**Fix**: Add `MAX_ENTITY_DEPTH = 50`, a `visited_ids` set, and skip entities already visited.

---

### [C5] `collect_events()` Crashes on `None` Return from `collect_from_db()`
**File**: `spiderfoot/correlation.py:499-529`
**Category**: Correlation Correctness
**Issue**: `collect_from_db()` returns `None` when `build_db_criteria()` fails. `collect_events()` assigns this to `events` at step 0. The next iteration calls `refine_collection(matchrule, events)` which calls `events[:]` on `None`, raising `TypeError`. This crashes the correlator mid-run, losing results from all already-processed rules.
**Why it matters for SpiderFoot**: A single malformed rule or edge case in criteria building destroys the entire correlation run, not just the one rule.
**Fix**: Guard `if events is None: log error; return []` after the step 0 assignment.

---

### [C6] Content-Disposition Header Built From Unsanitized User-Controlled Scan Name
**File**: `spiderfoot/blueprints/api.py:1190,1213,1318,1344,1456,1492,1538`
**Category**: Security
**Issue**: All export endpoints build `Content-Disposition: attachment; filename={scan_name}-SpiderFoot.csv` where `scan_name` comes directly from the database (user-supplied at scan creation). The value is not quoted, not sanitized for CRLF or `;`. A scan name containing `\r\n` or `; filename=malware.exe` enables header injection.
**Why it matters for SpiderFoot**: An attacker who can create scans (any authenticated user) can craft scan names that manipulate download behavior for other users exporting results.
**Fix**: Strip all characters except `[a-zA-Z0-9._-]` from scan name and always quote: `filename="{safe_name}.csv"`.

---

### [C7] CSRF Tokens Invalidated on Every Server Restart
**File**: `spiderfoot/app.py:67,193-208`
**Category**: Authentication & Sessions
**Issue**: `SECRET_KEY = os.urandom(32).hex()` is called fresh on every process start. This invalidates all existing sessions and CSRF tokens. Any in-flight form submission fails with 403 after a restart. With Docker auto-restart policies, this can happen frequently.
**Why it matters for SpiderFoot**: Users lose work (scan configurations, settings changes) on every server restart with no explanation beyond a 403 error.
**Fix**: Persist `SECRET_KEY` to the database or an environment variable. Generate once, store, reuse.

---

### [C8] `/api/optsexport` Leaks All API Keys in Plaintext
**File**: `spiderfoot/blueprints/api.py:919-944`
**Category**: Credential Security
**Issue**: The export filter skips keys where `":_" in opt` or `opt.startswith("_")` (internal settings). But module API keys use patterns like `sfp_shodan:api_key` (no leading underscore on `api_key`). These are NOT filtered. The export dumps every API key in plaintext as a downloadable `.cfg` file.
**Why it matters for SpiderFoot**: SpiderFoot stores dozens of API keys for Shodan, VirusTotal, Censys, etc. A single config export leaks all of them. These keys have direct financial value and security implications.
**Fix**: Add a filter excluding any opt containing `api_key`, `apikey`, `password`, `secret`, or `token`.

---

## High Findings

### [H1] Plaintext Password Storage in passwd File
**File**: `spiderfoot/app.py:13-36,168-179`
**Category**: Authentication & Sessions
**Issue**: `_load_passwd_file()` reads `username:password` as plaintext. Auth comparison uses `_hmac.compare_digest(stored_password, password)` — comparing raw plaintext to raw plaintext. No hashing.
**Why it matters for SpiderFoot**: Anyone with filesystem access reads all credentials. In Docker shared volumes or backup scenarios, passwords are trivially extracted.
**Fix**: Hash with `bcrypt` at storage time; compare with `bcrypt.checkpw()`.

---

### [H2] `removeUrlCreds()` Uses Broken `re.IGNORECASE` — Positional Arg Interpreted as `count`
**File**: `sflib.py:1093-1115`
**Category**: Credential Security
**Issue**: `re.sub(pat, pats[pat], ret, re.IGNORECASE)` — the 4th positional arg to `re.sub` is `count`, not `flags`. `re.IGNORECASE` (value `2`) is interpreted as `count=2`, so only the first 2 occurrences are replaced and case-insensitive matching is NOT applied. Also missing patterns for `token=`, `secret=`, `apikey=`, `api_key=`, `access_token=`.
**Why it matters for SpiderFoot**: API keys in URLs are not properly redacted from logs. Case variations (`Key=`, `KEY=`) slip through. URLs with 3+ credential parameters only have the first 2 redacted.
**Fix**: Use `flags=re.IGNORECASE` (keyword arg). Add missing patterns.

---

### [H3] Modules Don't Check `res['code']` for None Before String Comparison
**File**: `modules/sfp_shodan.py:99`, `sfp_greynoise.py:123`, `sfp_securitytrails.py:115`, `sfp_censys.py:160`
**Category**: OSINT Data Integrity
**Issue**: When `fetchUrl()` encounters a network exception, it returns `{code: None}`. These modules compare `res['code'] in ["403", "401"]` — `None in [...]` is `False`, so auth/rate-limit errors on connection failures are silently ignored. The module continues consuming events without entering `errorState`.
**Why it matters for SpiderFoot**: A temporarily failing API doesn't trigger errorState, so the module keeps trying (and failing) for every event in the scan, wasting time and producing no results without warning.
**Fix**: Add `if res['code'] is None: self.error(...); return None` as the first check after fetchUrl.

---

### [H4] Watchdog-Killed Module Queue Not Immediately Drained
**File**: `sfscan.py:472-484,576-583`
**Category**: Concurrency & State
**Issue**: When the 1800s watchdog fires and sets `mod.errorState = True`, the module's `incomingEventQueue` is not drained. New events continue to be enqueued in the race window. The queue may have thousands of items, making `threadsFinished()` report queues as non-empty and holding the scan open long after real work is done.
**Why it matters for SpiderFoot**: Scans appear to hang after a module timeout, confusing users.
**Fix**: Immediately drain and null the `incomingEventQueue` when setting errorState.

---

### [H5] `ThreadPoolWorker` Exception Drops Task Without Setting Module `errorState`
**File**: `spiderfoot/threadpool.py:255-261`
**Category**: OSINT Data Integrity
**Issue**: When `handleEvent()` throws, the worker logs and does `break`. The failed task is dropped (no retry), and the module doesn't get `errorState` set — it continues receiving events and throwing, generating unbounded log spam.
**Why it matters for SpiderFoot**: A module with a persistent bug generates endless errors while producing zero results, wasting worker threads.
**Fix**: Set `errorState = True` on the failed module. Replace `break` with `continue`.

---

### [H6] `/api/query` Endpoint Exposes Full Database Including API Keys
**File**: `spiderfoot/blueprints/api.py:168-203`
**Category**: Security
**Issue**: The raw SQL endpoint accepts SELECT statements. While `mode=ro` prevents writes, any authenticated user can `SELECT val FROM tbl_config WHERE opt LIKE '%api_key%'` to extract all stored API keys. The endpoint is also available at the bare-root `/query` path.
**Why it matters for SpiderFoot**: In multi-user deployments, any user can extract every configured API key.
**Fix**: Restrict to specific tables (exclude `tbl_config`), or gate behind an admin flag, or remove entirely.

---

### [H7] `analysis_outlier()` Has No Minimum Sample Size — False Positives on Tiny Datasets
**File**: `spiderfoot/correlation.py:705-740`
**Category**: Correlation Correctness
**Issue**: With 3 events across 3 buckets, each bucket is 33%. The noisy guard (default 10%) passes. All 3 fire as outlier correlations simultaneously. Percentage-based thresholds are meaningless with fewer than ~10 samples.
**Why it matters for SpiderFoot**: False correlations create false confidence. An analyst seeing "outlier country detected" for a scan with only 3 geo-located IPs wastes investigation time.
**Fix**: Add `MIN_BUCKETS = 10` guard; skip outlier analysis for small datasets.

---

### [H8] `event_extract()` Crashes on 3-Level Field Paths in Headlines
**File**: `spiderfoot/correlation.py:399-403`
**Category**: Correlation Correctness
**Issue**: `key, field = field.split(".")` with no `maxsplit` raises `ValueError: too many values to unpack` on 3-level paths like `source.entity.type`. The `build_correlation_title()` function uses `re.findall(r"{([a-z\.]+)}", title)` on headlines, so a headline containing `{source.entity.type}` triggers this crash.
**Why it matters for SpiderFoot**: A single headline typo in a YAML rule crashes the entire correlator.
**Fix**: Use `field.split(".", 1)` in all three locations (lines 401, 422, 554).

---

### [H9] `sfp_shodan` Emits `SOFTWARE_USED` Not Listed in `producedEvents()`
**File**: `modules/sfp_shodan.py:322,84-89`
**Category**: Module Safety
**Issue**: The module emits `SOFTWARE_USED` at line 322 but doesn't declare it in `producedEvents()`. This bypasses the module selection UI — users selecting "software detection" modules won't see Shodan listed.
**Why it matters for SpiderFoot**: OSINT data is produced but invisible in the module dependency graph.
**Fix**: Add `'SOFTWARE_USED'` to `producedEvents()`.

---

### [H10] `sfp_hunter` Never Sets `errorState` on API Auth Failures
**File**: `modules/sfp_hunter.py:97-108`
**Category**: Module Safety
**Issue**: No check for 401/403/429 HTTP codes. Invalid API key causes every call to return an error JSON, `handleEvent()` tries `data['data']` which raises `KeyError`, propagating up to crash the calling context rather than the Hunter module itself.
**Why it matters for SpiderFoot**: Wastes rate-limited API quota on a key known to be invalid, and the error is attributed to the wrong module.
**Fix**: Add `if res['code'] in ['401', '403', '429']: self.errorState = True; return None`.

---

### [H11] Unbounded `incomingEventQueue` — No Backpressure
**File**: `sfscan.py:353,524-527`
**Category**: Performance
**Issue**: Each module's `incomingEventQueue` is `queue.Queue()` with no maxsize. A DNS brute-forcer producing 50K subdomains dispatches 50K x deepcopy() x N modules simultaneously into unbounded queues. Slow API modules accumulate indefinitely large backlogs.
**Why it matters for SpiderFoot**: Memory exhaustion on large scans crashes the process, losing all results.
**Fix**: Create queues with `maxsize=1000` and use `put()` with timeout for backpressure.

---

### [H12] Unbounded Multi-Export Accumulates Entire Database in Memory
**File**: `spiderfoot/blueprints/api.py:1283-1354`
**Category**: Performance
**Issue**: `scaneventresultexportmulti` accepts unlimited comma-separated scan IDs. `data = data + dbh.scanResultEvent(id)` creates new list objects each iteration (O(n^2)). No cap on results per scan or total.
**Why it matters for SpiderFoot**: A single authenticated request can exhaust server memory.
**Fix**: Limit max IDs to 10. Stream output with `stream_with_context`.

---

### [H13] `analysis_threshold()` Has Inverted Loop Logic
**File**: `spiderfoot/correlation.py:750-773`
**Category**: Correlation Correctness
**Issue**: Buckets are deleted when any counted value does NOT fall within `[minimum, maximum]`. For buckets with multiple distinct values, if even one value has count < minimum, the whole bucket is deleted — even if most values qualify.
**Why it matters for SpiderFoot**: Rules using threshold with multi-value buckets silently drop valid correlations.
**Fix**: Delete only if NO value meets the threshold (use `any()` check).

---

### [H14] Scan Progress Duplicated Between `ui.py` and `fragments.py` With Diverging Logic
**File**: `spiderfoot/blueprints/ui.py:19-141`, `fragments.py:145-197`
**Category**: Architecture
**Issue**: Both files independently compute scan progress, type counts, and findings. `INLINE_TYPES` is defined inline in both. They are already slightly divergent (correlation counting differs).
**Why it matters for SpiderFoot**: Code drift causes the dashboard and the HTMX fragment to show different data.
**Fix**: Extract shared `scan_list_service.py` called by both.

---

## Medium Findings

### [M1] `sflib.py` Is a 1660-Line God Object
**File**: `sflib.py` (entire)
**Category**: Architecture
**Issue**: Six distinct responsibility clusters: logging (60 LOC), config serialization (180 LOC), module registry (110 LOC), DNS/network (300 LOC), HTTP/fetch (270 LOC), cert/SSL/CVE/search (340 LOC). Every module depends on the entire object, making unit testing impossible without full mocking.
**Fix**: Extract `SpiderFootDnsClient`, `SpiderFootHttpClient`, `SpiderFootCertParser` as standalone classes. `SpiderFoot` becomes a thin facade.

---

### [M2] `'unsafe-inline'` + `'unsafe-eval'` in CSP Renders XSS Protection Decorative
**File**: `spiderfoot/app.py:99-107`
**Category**: Security
**Issue**: CSP script-src includes `'unsafe-inline' 'unsafe-eval'`. Any XSS payload with inline `<script>` executes without restriction. `unsafe-eval` is required only because Alpine.js standard build uses `eval()`.
**Fix**: Switch to `@alpinejs/csp` build (no eval needed). Move inline scripts to files. Implement CSP nonces.

---

### [M3] Missing Session Cookie Security Flags
**File**: `spiderfoot/app.py:59-108`
**Category**: Authentication & Sessions
**Issue**: No `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, or `SESSION_COOKIE_SECURE` configuration.
**Fix**: Add all three: `HttpOnly=True`, `SameSite='Lax'`, `Secure=True` (when HTTPS).

---

### [M4] Unbounded Recursive Redirect in `fetchUrl()` via Refresh Header
**File**: `sflib.py:1389-1410`
**Category**: Logic & Correctness
**Issue**: `fetchUrl()` recursively calls itself on `Refresh` headers with no depth counter. A malicious server causes `RecursionError` (~1000 frames deep), crashing the scan thread.
**Fix**: Add `_redirectDepth` parameter, increment per call, bail at 10.

---

### [M5] CSV Export Has No Formula Injection Protection
**File**: `spiderfoot/blueprints/api.py:1119-1154`
**Category**: Security
**Issue**: Event data written to CSV via `csv.writer` with no sanitization. Fields starting with `=`, `+`, `-`, `@` are interpreted as formulas in Excel/LibreOffice.
**Why it matters for SpiderFoot**: OSINT data from untrusted sources (DNS TXT records, WHOIS fields) can contain formula payloads. Analysts opening CSV exports in spreadsheets are vulnerable.
**Fix**: Prefix cell values starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote.

---

### [M6] Certificate CN Substring Match Is Fragile
**File**: `sflib.py:1044-1051`
**Category**: Logic & Correctness
**Issue**: `if "cn=" + fqdn in ret['issued'].lower()` — `evil.example.com` matches a check for `example.com` because it's a substring. Could suppress mismatch warnings for subdomain takeover scenarios.
**Fix**: Parse CN properly — extract the exact CN= field value and compare with equality.

---

### [M7] Event ID Collision Risk With `randint(0, 99999999)`
**File**: `spiderfoot/event.py:55`
**Category**: Logic & Correctness
**Issue**: For events of the same type from the same module at close timestamps, the birthday probability becomes meaningful around 10K events. A hash collision kills the storage module (INSERT constraint violation), losing ALL subsequent events.
**Fix**: Use `random.SystemRandom().getrandbits(64)` or `uuid.uuid4()`.

---

### [M8] `clean_user_input()` Re-Introduces `"` and `&` After html.escape()
**File**: `spiderfoot/blueprints/api.py:62-72`
**Category**: Security
**Issue**: `html.escape(item, True)` escapes `"` to `&quot;`, then `.replace("&quot;", "\"")` restores it. The `"` flows into Content-Disposition filenames (see C6).
**Fix**: Remove the `.replace()` calls, or use a separate sanitizer for non-HTML contexts.

---

### [M9] `sfp_greynoise` Sets `errorState` on Normal "IP Not Seen" Empty Responses
**File**: `modules/sfp_greynoise.py:136-139`
**Category**: Module Safety
**Issue**: Network failure returns `res = {}` (falsy). The module interprets this as "API key rejected" and kills itself. All subsequent IPs in the scan are skipped.
**Fix**: Check `response['code'] is None` first (network error) vs `res` empty (no data).

---

### [M10] `notifyListeners()` Depth-1000 Guard Doesn't Set `storeOnly` on Termination
**File**: `spiderfoot/plugin.py:367-377`
**Category**: OSINT Data Integrity
**Issue**: At depth 1000, the loop exits without setting `storeOnly = True`. Events that should be suppressed are propagated. (Latent in threaded mode due to C1, but would surface if C1 is fixed.)
**Fix**: Set `storeOnly = True` when `depth >= max_depth`.

---

### [M11] `sfp_greynoise` Uses Non-Exclusive `if` Chains for Event Type Dispatch
**File**: `modules/sfp_greynoise.py:183-192`
**Category**: Module Safety
**Issue**: Three separate `if` statements (not `elif`) for event type matching. If `watchedEvents()` is extended without updating this block, `evtType`/`qryType` are never assigned, raising `UnboundLocalError`.
**Fix**: Convert to `elif` chain with `else: return`.

---

### [M12] IPv6 Regex in `targetTypeFromString()` Is Too Permissive
**File**: `spiderfoot/helpers.py:267`
**Category**: Logic & Correctness
**Issue**: `^[0-9a-f:]+$` matches any hex string like `"deadbeef"` or `"abc"`. A malware hash prefix pasted as a scan target gets misclassified as IPv6.
**Fix**: Use `^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$` or validate with `ipaddress.ip_address()`.

---

### [M13] `optValueToData()` Reads Arbitrary Filesystem Paths via `@` Prefix
**File**: `sflib.py:154-163`
**Category**: Security
**Issue**: `@/etc/passwd` in a config option opens the file with no path restriction. An admin user with UI access can read any server file.
**Fix**: Restrict `@filename` loading to the SpiderFoot data directory with `os.path.realpath()` check.

---

### [M14] `sfp_tool_nmap` Doesn't Check Executable Permissions on Binary Path
**File**: `modules/sfp_tool_nmap.py:116-135`
**Category**: Module Safety
**Issue**: Only `os.path.isfile()` is checked. No `os.access(exe, os.X_OK)` check. User-supplied path could point to any file.
**Fix**: Add `os.access(exe, os.X_OK)` check.

---

### [M15] EVENT_CATEGORIES Incomplete — Key Event Types Fall Into "Other"
**File**: `spiderfoot/blueprints/fragments.py:17-87`
**Category**: Tech Debt
**Issue**: `SOFTWARE_USED`, `DEVICE_TYPE`, `TCP_PORT_OPEN_BANNER`, `RAW_RIR_DATA`, `CO_HOSTED_SITE_DOMAIN`, `AFFILIATE_INTERNET_NAME` all go to "Other" bucket in the UI summary.
**Fix**: Add missing event types to appropriate categories.

---

### [M16] Correlation YAML Validator Doesn't Check Per-Method Required Fields
**File**: `spiderfoot/correlation.py:1036-1042`
**Category**: Correlation Correctness
**Issue**: `analysis_outlier()` accesses `rule['maximum_percent']` with no `.get()` fallback. A YAML rule with `method: outlier` but missing `maximum_percent` raises `KeyError` mid-run. The validator marks these fields as optional.
**Fix**: Add per-method required field validation in `check_rule_validity()`.

---

### [M17] Progress Heuristic Is Misleading
**File**: `spiderfoot/blueprints/fragments.py:193`, `ui.py:90`
**Category**: Tech Debt
**Issue**: `min(95, max(5, len(mod_summary) * 3))` — a 32-module scan shows 95% immediately. Never reaches 100%.
**Fix**: Replace with animated indicator or add "Based on active modules" caveat.

---

### [M18] Log Fragment HTMX Polls Every 3s With No Backoff After Scan Completes
**File**: `spiderfoot/templates/fragments/results_log.html`
**Category**: Performance
**Issue**: `hx-trigger="every 3s"` with no conditional backoff. 10 open tabs = ~200 req/min to Flask after scan is done.
**Fix**: Use `hx-trigger="every 3s[scanRunning]"` with Alpine.js state or return `HX-Trigger: stop` on completion.

---

### [M19] Timestamp Division by 1000 Inconsistent Between API and Fragment Routes
**File**: `spiderfoot/blueprints/api.py:444`, `fragments.py:328-332`
**Category**: Tech Debt
**Issue**: `api.py` unconditionally divides by 1000. `fragments.py` conditionally divides if `> 9999999999`. Represents two different understandings of the data format.
**Fix**: Standardize: always divide by 1000.

---

## Low Findings

### [L1] `sfp_shodan` Continues API Calls After `errorState` Set Mid-Loop
**File**: `modules/sfp_shodan.py:259`
**Category**: Module Safety
**Issue**: `errorState` set on 401/403 but the `for addr in qrylist` loop continues calling the API.
**Fix**: Add `if self.errorState: return` inside the loop.

---

### [L2] `sfp_virustotal` Missing 401/403 Check in `queryIp()`
**File**: `modules/sfp_virustotal.py`
**Category**: Module Safety
**Issue**: `queryDomain()` has auth error handling but `queryIp()` does not.
**Fix**: Add consistent auth error handling.

---

### [L3] `sfp_crt` Has No `errorState` Setting
**File**: `modules/sfp_crt.py`
**Category**: Module Safety
**Issue**: No explicit `errorState` handling on any error path.
**Fix**: Add `errorState = True` on persistent failures.

---

### [L4] Hardcoded `time.sleep()` in Multiple Modules
**File**: `sfp_shodan.py`, `sfp_abstractapi.py`, `sfp_crt.py`, `sfp_securitytrails.py`
**Category**: Tech Debt
**Issue**: Hardcoded sleep values (0.5-15s) instead of configurable `delay` opts. Blocks worker threads. `sfp_censys.py` shows the correct pattern: `time.sleep(self.opts['delay'])`.
**Fix**: Follow the `sfp_censys.py` pattern: add `delay` to opts dict.

---

### [L5] Collections Don't Short-Circuit on Zero Results
**File**: `spiderfoot/correlation.py:862-867`
**Category**: Performance
**Issue**: All collections execute even if an earlier one returns zero results.
**Fix**: Short-circuit when collection 0 returns empty.

---

### [L6] `sfcli.py` Version Hardcoded at "4.0.0" While App Is 5.0.2
**File**: `sfcli.py:57`
**Category**: Tech Debt
**Issue**: Version string mismatch confuses users.
**Fix**: Import `__version__` from `spiderfoot`.

---

### [L7] No Module Interface Validation at Load Time
**File**: `spiderfoot/helpers.py:121-172`
**Category**: Tech Debt
**Issue**: A module that forgets to override `handleEvent()` loads successfully and silently does nothing. No startup check for required method overrides.
**Fix**: Log warning if `producedEvents() == []` for non-storage modules.

---

### [L8] `import time as _time` Inside Function Bodies
**File**: `spiderfoot/blueprints/fragments.py:332,376`
**Category**: Tech Debt
**Issue**: Standard library import inside function body on every HTTP request.
**Fix**: Move to top of file.

---

### [L9] Export Links Hardcode Legacy Bare-Root Paths
**File**: `spiderfoot/templates/pages/scan_results.html:59-70`
**Category**: Architecture
**Issue**: `<a href="/scaneventresultexportmulti?ids=...">` uses legacy path instead of `url_for('api...')`.
**Fix**: Use `url_for()` pointing to `/api/` prefix.

---

### [L10] Unit Tests Cover Only Module Metadata, Not `handleEvent()` Logic
**File**: `test/unit/modules/` (all ~200 files)
**Category**: Tech Debt
**Issue**: Tests verify `opts`, `setup`, `watchedEvents`, `producedEvents` — not the actual event processing logic.
**Fix**: Add tests with mocked `fetchUrl()` that assert expected events are emitted.

---

### [L11] `|tojson` in Script Tags — Safe But Undocumented
**File**: `spiderfoot/templates/pages/scan_new.html:15`
**Category**: Security
**Issue**: Flask's `tojson` escapes `</script>` via markupsafe — safe but not commented, creating a maintenance trap.
**Fix**: Add a comment explaining why it's safe.

---

### [L12] No `|safe` Filter Usage — Positive Finding
**File**: All templates
**Category**: Security
**Issue**: Zero `|safe` uses found across 29 templates. HTML is pre-escaped in Python with `markupsafe.Markup()`. Correct pattern.
**Fix**: None needed.

---

### [L13] Dual API Blueprint Registration Doubles Attack Surface
**File**: `spiderfoot/app.py:116-123`
**Category**: Architecture
**Issue**: Every endpoint exists at both `/api/*` and `/*`. No deprecation plan or timeline for removing root-level routes.
**Fix**: Add `X-Deprecated: true` header on compat blueprint. Document removal milestone.

---

### [L14] ~585 LOC of Business Logic in View Layer (`fragments.py`)
**File**: `spiderfoot/blueprints/fragments.py:515-742`
**Category**: Architecture
**Issue**: Event categorization, badge colors, data formatting, deduplication — none depends on Flask. All testable independently but buried in the view blueprint.
**Fix**: Extract to `spiderfoot/services/event_service.py`.

---

## Summary Table

| Severity | Count | Categories |
|----------|-------|-----------|
| CRITICAL | 8 | Data Integrity (3), Correlation (2), Security (2), Auth (1) |
| HIGH | 14 | Security (3), Data Integrity (2), Correlation (3), Module Safety (2), Performance (2), Architecture (1), Auth (1) |
| MEDIUM | 19 | Security (4), Logic (3), Module Safety (3), Correlation (1), Architecture (1), Tech Debt (4), Performance (1), Data Integrity (1), Auth (1) |
| LOW | 14 | Module Safety (3), Tech Debt (5), Architecture (2), Security (2), Performance (1), Correlation (0) |

---

## Top 5 Fixes by Impact to SpiderFoot's Core Mission

1. **Fix C1 (storeOnly bypass)** — The entire deduplication architecture is disabled in production. This causes duplicate event cascades, inflated results, wasted API quota, and unreliable correlation counts. Single most impactful fix for data integrity.

2. **Fix C3 (maxstorage=1024)** — Change default to 0. Every certificate, large DNS record, and HTTP header set is silently corrupted in storage. This is a one-line fix with massive impact on data quality.

3. **Fix C4+C5 (correlation engine crashes)** — Add cycle detection to `enrich_event_entities()` and None guards to `collect_events()`. Without these, the correlation engine — the feature that produces actionable intelligence — can hang or crash silently.

4. **Fix C8+H2+H6 (credential leakage)** — Config export leaks API keys, removeUrlCreds has a broken flags parameter, and the query endpoint can SELECT from tbl_config. Three overlapping paths to credential leakage that should be fixed together.

5. **Fix C2+H5 (pipeline resilience)** — Add try/except around deepcopy and fix threadpool exception handling. Currently a single non-copyable event or a single unhandled exception in handleEvent() kills the entire scan or generates infinite error spam.

---

## Architectural Health Assessment

### Separation of Concerns: Poor
`sflib.py` (1660 LOC) is a god object mixing 6 distinct responsibilities. `fragments.py` contains ~585 LOC of business logic in the view layer. Scan list building is duplicated between `ui.py` and `fragments.py`. There is no service layer between the blueprints and the database.

### Testability: Poor
The entire module system depends on a `SpiderFoot` instance with no interface abstraction. Unit tests cover only module metadata, not event processing logic. The core event pipeline (`sfscan.py:waitForThreads()`) and correlation engine (`correlation.py:process_rule()`) appear under-tested relative to their complexity and criticality.

### Extensibility of Module System: Good with Caveats
The module pattern (watchedEvents/producedEvents/handleEvent) is clean and well-documented. The CLAUDE.md provides a reference template. However, there is no runtime validation that modules implement required methods, no enforced pattern for error handling (errorState compliance varies widely), and event types are magic strings with no enum or constant definition.

### Readiness for Multi-User / Cloud Deployment: Not Ready
- Plaintext password storage
- No password hashing
- API keys readable via query endpoint by any authenticated user
- Config export leaks all API keys
- CSP with unsafe-inline/unsafe-eval provides no XSS backstop
- SECRET_KEY regenerated on restart (session/CSRF instability)
- No session cookie security flags
- Global DNS resolver and SOCKS proxy overrides have process-level scope
- SQLite with single RLock is a write bottleneck under concurrent scan load
