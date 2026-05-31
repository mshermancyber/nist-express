// A small curated extract of CISA's Known Exploited Vulnerabilities
// catalog. In production this should be refreshed from the official
// JSON feed (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
// The static list is sufficient for demonstrating SBOM/VEX flow.

export const CISA_KEV_CVES = new Set<string>([
  'CVE-2021-44228', // Log4Shell
  'CVE-2021-45046',
  'CVE-2022-22965', // Spring4Shell
  'CVE-2022-22963',
  'CVE-2023-44487', // HTTP/2 Rapid Reset
  'CVE-2023-22515', // Confluence
  'CVE-2023-46604', // ActiveMQ
  'CVE-2023-4863',  // libwebp
  'CVE-2023-50164', // Struts
  'CVE-2024-3094',  // xz-utils backdoor
  'CVE-2024-21413', // Outlook
  'CVE-2024-21887', // Ivanti
  'CVE-2017-11882', // Office equation editor
  'CVE-2014-0160',  // Heartbleed
  'CVE-2017-5638',  // Struts (Equifax)
  'CVE-2019-19781', // Citrix ADC
  'CVE-2020-1472'   // ZeroLogon
]);
