# Sentinel

Sentinel helps a developer trace a security finding to its source, review the fix, and verify the change. The public demo uses two real commits from this repository.

**[Open Sentinel](https://sentinel-two-chi.vercel.app/) · [Replay the verified fix](https://sentinel-two-chi.vercel.app/?case=verified) · [See the GitHub diff](https://github.com/Arjun1443/Sentinel/compare/042bb9ea0a170b254297b8d72b682682da3c9f17...16654c9e991ccf5eba76ae65f95214c20410563a)**

## Give the judges a 90-second walkthrough

1. Open **Replay the verified fix**. Sentinel checks the two Git blob digests, rescans `vercel.json`, and reads the current site's response header. The single-file score moves from 96 to 100 when the form destination policy is added.
2. Open the baseline finding and its suggested patch. The GitHub diff, regression test and [passing CI run](https://github.com/Arjun1443/Sentinel/actions/runs/44478067576) are linked. An independent Semgrep CE run reports one matching rule before the change and zero afterward. Download either SARIF receipt.
3. In **Ask this scan**, ask “What changed?” or “How do I verify the fix?” The on-device classifier selects an intent and Sentinel answers using this review's findings and file references.
4. In **Samples**, choose **Check sample dependency**. Sentinel queries OSV for an exact npm version and links matching advisories. **GitHub** also audits exact versions while scanning public repositories.
5. Export the current review as Markdown or SARIF. In **Local files** you can also import an existing SARIF 2.1.0 report.

## What runs where

| Entry point | Data and behavior |
| --- | --- |
| Public GitHub scan | Resolves the default branch or an optional full commit SHA. Reads up to 40 eligible files at a pinned commit with a 2 MB aggregate input cap. Prioritizes manifests and configuration, skips vendored directories, and reports coverage and unreadable files. |
| Two-revision comparison | Scans a baseline and current commit. Compares matches in shared files and qualifies partial coverage. A selectable local history keeps the last eight distinct public revisions and scores in this browser. |
| Dependency audit | Extracts exact pins from simple PyPI requirements, npm manifests and modern npm lockfiles. Checks up to 32 package versions using OSV. Shows unresolved declarations, coverage limits, external failures, source severity when available and advisory links. |
| Local review | Reads selected text files or a SARIF report in the browser. Local source, snippets and questions stay in the browser. The advisory checkbox sends only a package's name, ecosystem and version. |
| On-device assistant | Multinomial naïve Bayes routes six question types. Inverse-document-frequency weighting locates a mentioned finding. Citations use the current or baseline evidence. Unrecognized questions get an explicit scope response. |
| Optional model brief | An allowlisted rule ID selects a catalog entry on the server. Groq, when configured, or a free-model Vercel AI Gateway route can paraphrase its impact, fix and validation. The interface identifies live model output or rule-catalog fallback. |
| Semgrep | Three checked-in Community Edition rules run in CI and produce a downloadable SARIF artifact. The two case receipts are included. Browser and public-repository scans use Sentinel's built-in rules. |

## Reproduce locally

Use Node.js 20 or newer and a full Git clone for historical replay.

~~~sh
npm ci
npm test
node scripts/verify-case.mjs
node scripts/train-intents.mjs
npx vercel dev
~~~

The case script loads both original files from Git and verifies their object IDs, scores and comparison. The training script checks that the committed model is reproducible from its 84 labeled training questions. Its 18-question phrasing check is deliberately small. It measures routing on this fixture set.

To independently rerun the case with Semgrep, install `semgrep==1.186.0` into an isolated Python environment and run `python scripts/semgrep-case.py`. Both SARIF receipts are regenerated in `public/evidence/`. To review a downloaded single-line patch, inspect it first, then run `git apply --check --unidiff-zero patchfile.patch` against the matching revision.

## Scope and scoring

Start at 100. Deduct 18 per critical finding, 10 per high, 4 per medium and 1 per low. Potential embedded credentials deduct 15 extra. Ungraded advisories remain visible and carry zero weight. Scores are floored at zero. The dashboard identifies the input scope and scan coverage.

Static patterns can miss issues and produce false positives. A disappearing match calls for an application-level check. The demo verifies one browser policy in one production file. Source matches are capped at 300 displayed rows. The OSV check uses simple exact versions and bounded result pages. The app labels partial or unavailable lookups. App-specific authorization, runtime behavior and deep data-flow review require separate verification.

## Deployment

Vercel serves `public/` and the three Node functions in `api/`. No secret is required for the verified case, on-device assistant, public GitHub review, or package lookup. To use Groq intentionally, configure `GROQ_API_KEY` in this project's server-side environment. Optional `GROQ_MODEL` defaults to `llama-3.3-70b-versatile`. The Vercel AI Gateway adapter uses project OIDC and the free-model ID `nvidia/nemotron-3.5-lightning-free` when gateway access is available.

[OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) · [MDN form-action reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action)
