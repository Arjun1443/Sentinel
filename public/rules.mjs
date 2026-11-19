export const levels = ['critical', 'high', 'medium', 'low', 'review'];
export const weights = { critical: 18, high: 10, medium: 4, low: 1, review: 0 };

// The brief endpoint accepts only these rule IDs. User source never enters its prompt.
export const rules = {
  'CFG-01': {
    level: 'high',
    title: 'Debug mode enabled',
    group: 'Configuration',
    impact: 'Detailed diagnostic information can reach people using the production app.',
    fix: 'Disable debugging in production and retain diagnostics in restricted logs.',
    verify: 'In a staging release, confirm an ordinary error returns the intended public error page.',
  },
  'TLS-01': {
    level: 'high',
    title: 'Certificate verification disabled',
    group: 'Transport',
    impact: 'A client with certificate verification disabled can accept an untrusted server identity.',
    fix: 'Enable certificate verification. Configure a trusted CA bundle if the service uses an internal CA.',
    verify: 'Run a normal request against the intended service with certificate checks enabled.',
  },
  'SEC-01': {
    level: 'critical',
    title: 'Possible embedded credential',
    group: 'Secrets',
    impact:
      'A credential committed to source may be available to everyone who can read the repository and its history.',
    fix: 'Check whether the value is active. Rotate it if necessary and load the replacement from a secret manager.',
    verify:
      'Confirm the old credential is revoked, the service uses the replacement and a rescan clears the match.',
  },
  'PY-01': {
    level: 'high',
    title: 'Review pickle deserialization',
    group: 'Data handling',
    impact:
      'Pickle assumes a trusted producer. Data crossing an untrusted boundary needs a safer representation.',
    fix: 'Use a data-only format for external input and validate its schema.',
    verify: 'Run normal round-trip tests with representative data and check schema validation.',
  },
  'WEB-01': {
    level: 'medium',
    title: 'Review HTML insertion',
    group: 'Browser',
    impact: 'The browser interprets assigned HTML as markup. The origin of the value determines the risk.',
    fix: 'Use textContent for plain text. For required markup, review sanitization and its configuration.',
    verify: 'Check that expected text and formatting render correctly after the change.',
  },
  'SQL-01': {
    level: 'high',
    title: 'Review interpolated database query',
    group: 'Data handling',
    impact: 'Combining query text and data makes the database boundary harder to enforce.',
    fix: 'Pass values separately through the database driver’s parameter-binding interface.',
    verify: 'Run existing query tests with ordinary data and confirm the same records are returned.',
  },
  'DEP-01': {
    level: 'low',
    title: 'Dependency version needs review',
    group: 'Dependencies',
    impact: 'A version range can resolve to different packages between installations.',
    fix: 'Capture the resolved versions in a lockfile and audit the lockfile.',
    verify: 'Rebuild in a clean environment and compare the installed versions.',
  },
  'CSP-01': {
    level: 'medium',
    title: 'Form destinations are unrestricted by this policy',
    group: 'Browser policy',
    impact:
      'A Content Security Policy needs an explicit form-action directive to restrict form destinations. The default-src directive does not cover form submissions.',
    fix: "List the form destinations the app actually needs. For Sentinel, form-action 'self' allows same-origin submissions.",
    verify:
      'Run the header regression test and inspect the Content-Security-Policy response header on the deployed page.',
    reference:
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action',
  },
  'SAST-01': {
    level: 'review',
    title: 'Imported static analysis finding',
    group: 'Static analysis',
    impact:
      'The source scanner reported a match at this location. Review its rule and the surrounding code.',
    fix: 'Confirm the rule applies, follow the scanner’s remediation guidance, and review the change.',
    verify: 'Rerun the same scanner and ruleset after the change and check the application tests.',
  },
  'OSV-01': {
    level: 'review',
    title: 'Dependency advisory match',
    group: 'Dependencies',
    impact:
      'OSV lists the selected package version in a published advisory. Application exposure requires review of how the dependency is used.',
    fix: 'Review the linked record, choose a compatible patched release, update the lockfile and run the application tests.',
    verify: 'Audit the resolved replacement version and check that the same advisory is absent.',
  },
};
