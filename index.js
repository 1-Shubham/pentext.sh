/**
 * Pentrix.sh — App Logic
 * AI-powered pentesting simulation suite
 * Powered by Anthropic Claude API
 */

const API_URL = "https://api.anthropic.com/v1/messages";
const MODEL   = "claude-sonnet-4-20250514";

/* ─────────────────────────────────────────
   API KEY MANAGEMENT
───────────────────────────────────────── */

function getApiKey() {
  return localStorage.getItem("pentrix_api_key") || "";
}

function saveApiKey() {
  const key = document.getElementById("api-key-input").value.trim();
  if (!key) {
    alert("Please enter a valid API key.");
    return;
  }
  localStorage.setItem("pentrix_api_key", key);
  updateApiBanner();
  closeApiModal();
}

function clearApiKey() {
  localStorage.removeItem("pentrix_api_key");
  document.getElementById("api-key-input").value = "";
  updateApiBanner();
}

function updateApiBanner() {
  const banner = document.getElementById("api-banner");
  if (getApiKey()) {
    banner.classList.add("hidden");
  } else {
    banner.classList.remove("hidden");
  }
}

function openApiModal() {
  const modal = document.getElementById("modal-overlay");
  modal.classList.add("open");
  const existing = getApiKey();
  if (existing) {
    document.getElementById("api-key-input").value = existing;
  }
}

function closeApiModal() {
  document.getElementById("modal-overlay").classList.remove("open");
}

/* ─────────────────────────────────────────
   TAB SWITCHING
───────────────────────────────────────── */

function switchTab(name, btn) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById("tab-" + name).classList.add("active");
}

/* ─────────────────────────────────────────
   OPTION TOGGLE
───────────────────────────────────────── */

function toggleOpt(id) {
  document.getElementById(id).classList.toggle("sel");
}

function getOpts(ids) {
  return ids
    .filter(id => document.getElementById(id)?.classList.contains("sel"))
    .map(id => document.getElementById(id).textContent.trim());
}

/* ─────────────────────────────────────────
   TERMINAL HELPERS
───────────────────────────────────────── */

function clearTerm(id) {
  document.getElementById(id).innerHTML = "";
}

function writeLine(id, text, cls = "info") {
  const el   = document.getElementById(id);
  const span = document.createElement("span");
  span.className = "line " + cls;
  span.textContent = text;
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

function writeCursor(id) {
  const el   = document.getElementById(id);
  const span = document.createElement("span");
  span.className = "line muted blink";
  span.id = id + "-cursor";
  span.textContent = "█";
  el.appendChild(span);
}

function removeCursor(id) {
  const c = document.getElementById(id + "-cursor");
  if (c) c.remove();
}

/* ─────────────────────────────────────────
   CLASSIFY LINE FOR COLOUR
───────────────────────────────────────── */

function classifyLine(line) {
  if (!line.trim()) return "muted";
  const u = line.toUpperCase();
  if (line.startsWith("[+]") || u.includes("OPEN")   || u.includes("SUCCESS")) return "success";
  if (line.startsWith("[!]") || u.includes("WARNING") || u.includes("VULN"))   return "warn";
  if (line.startsWith("[-]") || u.includes("ERROR")   || u.includes("FAIL"))   return "err";
  if (line.startsWith("[*]") || u.includes("STARTING") || u.includes("SCAN"))  return "cmd";
  if (line.match(/https?:\/\//) || line.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) return "blue";
  return "info";
}

/* ─────────────────────────────────────────
   CLAUDE API CALL
───────────────────────────────────────── */

async function callClaude(prompt, termId) {
  const apiKey = getApiKey();

  clearTerm(termId);

  if (!apiKey) {
    writeLine(termId, "[-] ERROR: No API key configured.", "err");
    writeLine(termId, "[!] Click 'Configure API Key' in the banner above.", "warn");
    return;
  }

  writeLine(termId, "[*] Initializing module...", "cmd");
  writeCursor(termId);

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true"
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1000,
        system: `You are a pentesting terminal simulator. Output ONLY raw terminal lines — no markdown, no code blocks, no asterisks, no headers, no backticks.
Use realistic, detailed output that a real security tool would produce.
Prefix important findings with [+], warnings with [!], errors with [-], general info with [*].
For each finding include specific technical details: port numbers, CVE IDs where relevant, service versions, protocol names, risk levels.
Output 18-30 lines of realistic terminal output. Keep it authentic and technical.`,
        messages: [{ role: "user", content: prompt }]
      })
    });

    removeCursor(termId);

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      writeLine(termId, "[-] API Error " + res.status + ": " + (err.error?.message || res.statusText), "err");
      if (res.status === 401) {
        writeLine(termId, "[!] Invalid or expired API key. Reconfigure above.", "warn");
      }
      return;
    }

    const data  = await res.json();
    const text  = (data.content || []).map(b => b.text || "").join("");
    const lines = text.split("\n");

    for (const line of lines) {
      if (!line.trim()) {
        writeLine(termId, "", "muted");
        continue;
      }
      writeLine(termId, line, classifyLine(line));
    }

    writeLine(termId, "", "muted");
    writeLine(termId, "[*] Scan complete.", "cmd");

  } catch (e) {
    removeCursor(termId);
    writeLine(termId, "[-] Network error: " + e.message, "err");
    writeLine(termId, "[!] Check your internet connection and API key.", "warn");
  }
}

/* ─────────────────────────────────────────
   TOOL: PORT SCANNER
───────────────────────────────────────── */

async function runPortScan() {
  const host  = document.getElementById("ps-host").value.trim();
  const range = document.getElementById("ps-range").value.trim() || "1-1024";

  if (!host) {
    clearTerm("port-out");
    writeLine("port-out", "[-] Error: no target specified", "err");
    return;
  }

  const opts = getOpts(["ps-common", "ps-web", "ps-db", "ps-ftp", "ps-vuln"]);
  const prompt = `Simulate a TCP port scan of target: ${host}
Port range: ${range}
Options enabled: ${opts.join(", ") || "default"}

Show each port result: state (open/closed/filtered), service name, version banner where available.
Highlight interesting open ports with [+].
${opts.includes("Check for Vulns") ? "For open ports, check for known CVEs and flag critical ones with severity." : ""}
Format like a real port scanner (masscan/nmap style).`;

  await callClaude(prompt, "port-out");
}

/* ─────────────────────────────────────────
   TOOL: NMAP
───────────────────────────────────────── */

async function runNmap() {
  const host  = document.getElementById("nm-host").value.trim();
  const type  = document.getElementById("nm-type").value;
  const flags = document.getElementById("nm-flags").value.trim();

  if (!host) {
    clearTerm("nmap-out");
    writeLine("nmap-out", "[-] Error: no target specified", "err");
    return;
  }

  const prompt = `Simulate this exact nmap command output:
nmap -${type} ${flags} ${host}

Generate AUTHENTIC nmap output including:
- Starting Nmap header line with version and timestamp
- Host discovery / ping results
- PORT, STATE, SERVICE, VERSION columns (tab-aligned)
- OS detection results if -O or -A flag
- NSE script output if --script flag given
- Timing stats at the bottom
Make it indistinguishable from real nmap output.`;

  await callClaude(prompt, "nmap-out");
}

/* ─────────────────────────────────────────
   TOOL: DNS LOOKUP
───────────────────────────────────────── */

async function runDNS() {
  const domain = document.getElementById("dns-domain").value.trim();
  const type   = document.getElementById("dns-type").value;

  if (!domain) {
    clearTerm("dns-out");
    writeLine("dns-out", "[-] Error: no domain specified", "err");
    return;
  }

  const opts   = getOpts(["dns-sub", "dns-zone", "dns-rev", "dns-spf"]);
  const prompt = `Simulate a DNS lookup for: ${domain}
Record type: ${type}
Options: ${opts.join(", ") || "standard lookup"}

Show realistic DNS records with TTL values, IP addresses, mail server priorities etc.
${opts.includes("Subdomain Enum") ? "Enumerate common subdomains (www, mail, ftp, api, dev, staging, admin, vpn, etc) with IPs." : ""}
${opts.includes("Zone Transfer") ? "Attempt zone transfer and show AXFR result (simulate success or failure)." : ""}
${opts.includes("SPF / DMARC Check") ? "Check SPF, DMARC, DKIM records and flag misconfigurations." : ""}
Format like real dig command output with ;; QUESTION SECTION, ;; ANSWER SECTION etc.`;

  await callClaude(prompt, "dns-out");
}

/* ─────────────────────────────────────────
   TOOL: WHOIS
───────────────────────────────────────── */

async function runWhois() {
  const target = document.getElementById("wi-target").value.trim();

  if (!target) {
    clearTerm("whois-out");
    writeLine("whois-out", "[-] Error: no target specified", "err");
    return;
  }

  const opts   = getOpts(["wi-reg", "wi-dates", "wi-ns", "wi-geo"]);
  const prompt = `Simulate a whois lookup for: ${target}
Options requested: ${opts.join(", ") || "standard whois"}

Generate realistic whois output with:
${opts.includes("Registrar Info") ? "- Registrar name, IANA ID, URL, abuse contact" : ""}
${opts.includes("Expiry Dates") ? "- Creation date, updated date, expiry date" : ""}
${opts.includes("Nameservers") ? "- All nameservers (NS records)" : ""}
${opts.includes("IP Geolocation") ? "- ASN, network range, country, org, ISP, abuse contact" : ""}
- Domain status codes with EPP meaning
- DNSSEC status
Format exactly like real whois command output.`;

  await callClaude(prompt, "whois-out");
}

/* ─────────────────────────────────────────
   TOOL: WEB HACKING
───────────────────────────────────────── */

async function runWebHack() {
  const url = document.getElementById("wh-url").value.trim();

  if (!url) {
    clearTerm("web-out");
    writeLine("web-out", "[-] Error: no URL specified", "err");
    return;
  }

  const opts   = getOpts(["wh-headers", "wh-xss", "wh-sqli", "wh-csrf", "wh-dir", "wh-ssl", "wh-cors", "wh-cve"]);
  const prompt = `Simulate a web vulnerability assessment of: ${url}
Tests to perform: ${opts.join(", ") || "basic recon"}

For each test category, produce realistic tool output:
${opts.includes("HTTP Headers")    ? "- Check security headers: CSP, HSTS, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy. Flag missing/misconfigured ones." : ""}
${opts.includes("XSS Vectors")     ? "- Test XSS injection points in forms, URL params, headers. List payloads tried and any reflected/stored XSS found." : ""}
${opts.includes("SQL Injection")   ? "- Test SQL injection in params. Show payloads, error messages, boolean-based detection results." : ""}
${opts.includes("CSRF Detection")  ? "- Check for CSRF tokens in forms, SameSite cookie flags, Origin validation." : ""}
${opts.includes("Dir Busting")     ? "- Enumerate directories: /admin, /login, /api, /backup, /.git, /config, /wp-admin etc. Show status codes." : ""}
${opts.includes("SSL/TLS Audit")   ? "- Check TLS version, cipher suites, certificate validity, expiry, issuer, SANs." : ""}
${opts.includes("CORS Misconfig")  ? "- Test CORS with various Origin headers, show Access-Control headers returned." : ""}
${opts.includes("CVE Lookup")      ? "- Fingerprint server software and check against known CVEs with CVSS scores." : ""}

Rate each finding: CRITICAL / HIGH / MEDIUM / LOW / INFO
Be thorough and technically accurate.`;

  await callClaude(prompt, "web-out");
}

/* ─────────────────────────────────────────
   INIT
───────────────────────────────────────── */

document.addEventListener("DOMContentLoaded", () => {
  updateApiBanner();
});
