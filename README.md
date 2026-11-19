# Sentinel

Sentinel is a defensive static review dashboard for public GitHub repositories and local source files. Open the built-in demo, inspect the configuration findings and suggested patches, then click **Scan revised demo**. The sample moves from 79 to 99 with two fewer rule matches.

## Run locally

Use Node.js 20 or newer. Run `npm test` to check the rule engine. Use `npx vercel dev` for both the dashboard and GitHub endpoint. To run just the browser-based local and demo modes, serve `public/` with any static HTTP server.

## Deploy

Import this repository into Vercel. The `public/` directory serves the dashboard, and `api/repository.js` implements bounded GitHub ingestion. The baseline works without external credentials.

## Coverage and design

- GitHub review reads up to 24 supported text files from the default-branch commit using the GitHub API. Network access targets GitHub only. Repositories are never executed.
- Local files are read in the browser. Select the same filenames again to compare scans.
- Findings are rule matches for a limited set of configuration, credential, code and dependency-hygiene patterns. The dependency rule examines version declarations. Advisory lookup requires a future integration.
- Findings include rule, severity, file and line. GitHub evidence links point to a fixed commit. Possible credential values are redacted.
- A developer reviews and applies suggested configuration changes. Scan history is session-scoped. Comparison uses rule, path and occurrence order, so moving or reordering multiple matches in one file can affect identity.
- Scores describe the scanned files and configured rules. Independently run application tests after applying changes.

## Roadmap

Semgrep and advisory-backed dependency checks, validated Groq explanations based on redacted findings, durable history, and pull request review.
