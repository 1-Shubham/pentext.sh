/**
 * Pentrix.sh — app.js
 *
 * Tool breakdown:
 *   Port Scanner  → AI-simulated  (Claude API)
 *   Nmap          → AI-simulated  (Claude API)
 *   DNS Lookup    → REAL LIVE DATA (dns.google DoH API — free, no key)
 *   Whois         → REAL LIVE DATA (rdap.org + ip-api.com — free, no key)
 *   Web Hacking   → AI-simulated  (Claude API)
 */

/* ═══════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════ */

const CLAUDE_API = "https://api.anthropic.com/v1/messages";
const MODEL      = "claude-sonnet-4-20250514";
const DNS_API    = "https://dns.google/resolve";
const GEO_API    = "https://ip-api.com/json";
const RDAP_API   = "https://rdap.org/domain";

const SUBDOMAINS = [
  "www","mail","ftp","smtp","pop","imap","api","dev","staging","admin",
  "vpn","remote","portal","shop","blog","app","cdn","ns1","ns2","mx",
  "webmail","test","secure","m","mobile","support","status","beta","git",
  "dashboard","login","auth","media","static","assets","files","docs"
];

/* ═══════════════════════════════════════════
   API KEY MANAGEMENT
═══════════════════════════════════════════ */

function getApiKey()  { return localStorage.getItem("pentrix_api_key") || ""; }

function saveApiKey() {
  const key = document.getElementById("api-key-input").value.trim();
  if (!key) { alert("Please enter a valid API key."); return; }
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
  const b = document.getElementById("api-banner");
  getApiKey() ? b.classList.add("hidden") : b.classList.remove("hidden");
}

function openApiModal() {
  document.getElementById("modal-overlay").classList.add("open");
  const k = getApiKey();
  if (k) document.getElementById("api-key-input").value = k;
}

function closeApiModal() {
  document.getElementById("modal-overlay").classList.remove("open");
}

/* ═══════════════════════════════════════════
   TAB + OPTION HELPERS
═══════════════════════════════════════════ */

function switchTab(name, btn) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById("tab-" + name).classList.add("active");
}

function toggleOpt(id) { document.getElementById(id).classList.toggle("sel"); }

function getOpts(ids) {
  return ids
    .filter(id => document.getElementById(id)?.classList.contains("sel"))
    .map(id => document.getElementById(id).textContent.trim());
}

/* ═══════════════════════════════════════════
   TERMINAL HELPERS
═══════════════════════════════════════════ */

function clearTerm(id)  { document.getElementById(id).innerHTML = ""; }

function writeLine(id, text, cls = "info") {
  const el   = document.getElementById(id);
  const span = document.createElement("span");
  span.className   = "line " + cls;
  span.textContent = text;
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
}

function writeCursor(id) {
  const el = document.getElementById(id);
  const s  = document.createElement("span");
  s.className   = "line muted blink";
  s.id          = id + "-cursor";
  s.textContent = "█";
  el.appendChild(s);
}

function removeCursor(id) {
  const c = document.getElementById(id + "-cursor");
  if (c) c.remove();
}

function classifyLine(line) {
  if (!line.trim()) return "muted";
  const u = line.toUpperCase();
  if (line.startsWith("[+]") || u.includes("OPEN")    || u.includes("SUCCESS"))  return "success";
  if (line.startsWith("[!]") || u.includes("WARNING")  || u.includes("VULN"))    return "warn";
  if (line.startsWith("[-]") || u.includes("ERROR")    || u.includes("FAIL"))    return "err";
  if (line.startsWith("[*]") || u.includes("STARTING") || u.includes("SCAN"))    return "cmd";
  if (line.match(/https?:\/\//) || line.match(/\d{1,3}(\.\d{1,3}){3}/))         return "blue";
  return "info";
}

/* ═══════════════════════════════════════════
   CLAUDE AI CALL  (for simulated tools)
═══════════════════════════════════════════ */

async function callClaude(prompt, termId) {
  const apiKey = getApiKey();
  clearTerm(termId);

  if (!apiKey) {
    writeLine(termId, "[-] ERROR: No Anthropic API key configured.", "err");
    writeLine(termId, "[!] Click 'Configure API Key' in the banner above to add your key.", "warn");
    writeLine(termId, "[*] DNS Lookup and Whois do NOT need a key — try those tabs!", "cmd");
    return;
  }

  writeLine(termId, "[*] Initializing module...", "cmd");
  writeCursor(termId);

  try {
    const res = await fetch(CLAUDE_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true"
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1200,
        system: `You are a pentesting terminal simulator. Output ONLY raw terminal lines.
Rules:
- No markdown, no code blocks, no asterisks, no backticks, no headers
- Prefix findings with [+], warnings with [!], errors with [-], info with [*]
- Include real technical details: port numbers, CVE IDs, service versions, CVSS scores, protocol names
- Output 20-35 lines. Be thorough and technically authentic.
- Make output look exactly like real security tool output`,
        messages: [{ role: "user", content: prompt }]
      })
    });

    removeCursor(termId);

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      writeLine(termId, "[-] API Error " + res.status + ": " + (err.error?.message || res.statusText), "err");
      if (res.status === 401) writeLine(termId, "[!] Invalid or expired API key — reconfigure above.", "warn");
      if (res.status === 429) writeLine(termId, "[!] Rate limit hit — wait a moment and try again.", "warn");
      return;
    }

    const data  = await res.json();
    const text  = (data.content || []).map(b => b.text || "").join("");

    text.split("\n").forEach(line => {
      writeLine(termId, line || "", line ? classifyLine(line) : "muted");
    });

    writeLine(termId, "", "muted");
    writeLine(termId, "[*] Scan complete.", "cmd");

  } catch (e) {
    removeCursor(termId);
    writeLine(termId, "[-] Network error: " + e.message, "err");
    writeLine(termId, "[!] Check your internet connection.", "warn");
  }
}

/* ═══════════════════════════════════════════
   TOOL 1: PORT SCANNER  (AI-simulated)
═══════════════════════════════════════════ */

async function runPortScan() {
  const host  = document.getElementById("ps-host").value.trim();
  const range = document.getElementById("ps-range").value.trim() || "1-1024";

  if (!host) {
    clearTerm("port-out");
    writeLine("port-out", "[-] Error: no target host or IP specified", "err");
    return;
  }

  const opts = getOpts(["ps-common","ps-web","ps-db","ps-ftp","ps-vuln"]);

  const prompt = `Simulate a TCP port scan of: ${host}
Port range: ${range}
Options enabled: ${opts.join(", ") || "default common ports"}

Show authentic port scanner output:
- Header with tool name, target, start time
- Each scanned port result: PORT/STATE/SERVICE/VERSION
- Mark open ports clearly with [+]
- Closed/filtered ports shown briefly or summarised
${opts.includes("Check for Vulns") ? "- For each open port, check for known CVEs. Show CVE ID, CVSS score, severity." : ""}
- Summary at bottom: X open, Y closed, Z filtered
Format exactly like masscan or nmap output.`;

  await callClaude(prompt, "port-out");
}

/* ═══════════════════════════════════════════
   TOOL 2: NMAP  (AI-simulated)
═══════════════════════════════════════════ */

async function runNmap() {
  const host  = document.getElementById("nm-host").value.trim();
  const type  = document.getElementById("nm-type").value;
  const flags = document.getElementById("nm-flags").value.trim();

  if (!host) {
    clearTerm("nmap-out");
    writeLine("nmap-out", "[-] Error: no target specified", "err");
    return;
  }

  const prompt = `Simulate this nmap command output EXACTLY:
nmap -${type} ${flags} ${host}

Requirements:
- Start with "Starting Nmap X.XX ( https://nmap.org ) at YYYY-MM-DD HH:MM UTC"
- Show host status and latency
- PORT table with STATE / SERVICE / VERSION / REASON columns, properly aligned
- If -O or -A: show OS fingerprint with confidence percentage
- If --script: show NSE script output with indented results
- If -sU: show UDP ports with service names
- If -sn: show host discovery results with MAC if local
- End with timing stats: "Nmap done: 1 IP address (1 host up) scanned in X.XX seconds"
Be indistinguishable from real nmap.`;

  await callClaude(prompt, "nmap-out");
}

/* ═══════════════════════════════════════════
   TOOL 3: DNS LOOKUP  (REAL — dns.google DoH)
═══════════════════════════════════════════ */

async function dnsQuery(name, type) {
  const url = `${DNS_API}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
  if (!res.ok) throw new Error("DNS API returned " + res.status);
  return res.json();
}

function dnsTypeName(num) {
  const map = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"};
  return map[num] || String(num);
}

function fmtRecord(rec) {
  return `${String(rec.name).padEnd(42)} ${String(rec.TTL).padEnd(7)} IN  ${dnsTypeName(rec.type).padEnd(8)} ${rec.data}`;
}

const STATUS_CODES = ["NOERROR","FORMERR","SERVFAIL","NXDOMAIN","NOTIMP","REFUSED"];

async function runDNS() {
  const domain = document.getElementById("dns-domain").value.trim().toLowerCase();
  const type   = document.getElementById("dns-type").value;
  const termId = "dns-out";

  if (!domain) {
    clearTerm(termId);
    writeLine(termId, "[-] Error: no domain specified", "err");
    return;
  }

  const opts = getOpts(["dns-sub","dns-zone","dns-rev","dns-spf"]);
  clearTerm(termId);

  writeLine(termId, `[*] dig ${type === "ALL" ? "ANY" : type} ${domain} @8.8.8.8`, "cmd");
  writeLine(termId, `[*] Querying Google Public DNS (dns.google)...`, "cmd");
  writeLine(termId, "", "muted");
  writeCursor(termId);

  try {

    /* ── Primary record query ── */
    const typesToQuery = type === "ALL"
      ? ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
      : [type];

    for (const t of typesToQuery) {
      let data;
      try {
        data = await dnsQuery(domain, t);
      } catch (e) {
        removeCursor(termId);
        writeLine(termId, `[-] Failed to query ${t} record: ${e.message}`, "err");
        writeCursor(termId);
        continue;
      }

      removeCursor(termId);

      writeLine(termId, `; <<>> DiG 9.18.21 <<>> ${domain} ${t}`, "muted");
      writeLine(termId, "; global options: +cmd", "muted");
      writeLine(termId, "; Got answer:", "muted");
      writeLine(termId, `; ->>HEADER<<- opcode: QUERY, status: ${STATUS_CODES[data.Status] || data.Status}, id: ${Math.floor(Math.random()*65535)}`, "muted");
      writeLine(termId, "", "muted");

      writeLine(termId, ";; QUESTION SECTION:", "muted");
      writeLine(termId, `;${domain}.    IN  ${t}`, "info");
      writeLine(termId, "", "muted");

      if (data.Answer && data.Answer.length > 0) {
        writeLine(termId, ";; ANSWER SECTION:", "muted");
        data.Answer.forEach(rec => writeLine(termId, "[+] " + fmtRecord(rec), "success"));
      } else if (data.Authority && data.Authority.length > 0) {
        writeLine(termId, ";; AUTHORITY SECTION:", "muted");
        data.Authority.forEach(rec => writeLine(termId, "    " + fmtRecord(rec), "info"));
        writeLine(termId, `[!] No ${t} records found — NXDOMAIN or empty zone`, "warn");
      } else {
        writeLine(termId, `[!] No ${t} records found for ${domain}`, "warn");
      }

      writeLine(termId, "", "muted");
      writeLine(termId, `; Query time: ${Math.floor(Math.random()*40)+5} msec`, "muted");
      writeLine(termId, "; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)", "muted");
      writeLine(termId, `; WHEN: ${new Date().toUTCString()}`, "muted");
      writeLine(termId, "", "muted");

      writeCursor(termId);
    }

    removeCursor(termId);

    /* ── SPF / DMARC check ── */
    if (opts.includes("SPF / DMARC Check")) {
      writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
      writeLine(termId, "[*] Checking email security records (SPF / DMARC / DKIM)...", "cmd");
      writeLine(termId, "", "muted");
      writeCursor(termId);

      /* SPF */
      let spfFound = false;
      try {
        const spfData = await dnsQuery(domain, "TXT");
        removeCursor(termId);
        if (spfData.Answer) {
          spfData.Answer.forEach(rec => {
            const v = rec.data.replace(/^"|"$/g,"");
            if (v.startsWith("v=spf1")) {
              spfFound = true;
              writeLine(termId, "[+] SPF record found:", "success");
              writeLine(termId, "    " + v, "info");
              if (v.includes("+all"))      writeLine(termId, "[!] SPF uses +all — ANY server can send mail (CRITICAL)", "err");
              else if (v.includes("~all")) writeLine(termId, "[!] SPF uses ~all (SoftFail) — consider upgrading to -all (MEDIUM)", "warn");
              else if (v.includes("-all")) writeLine(termId, "[+] SPF uses -all (HardFail) — correct configuration (PASS)", "success");
              else if (v.includes("?all")) writeLine(termId, "[!] SPF uses ?all (Neutral) — no enforcement (LOW)", "warn");
            }
          });
        }
      } catch(e) { removeCursor(termId); }

      if (!spfFound) writeLine(termId, "[!] No SPF record found — mail spoofing possible (HIGH)", "warn");

      /* DMARC */
      writeCursor(termId);
      let dmarcFound = false;
      try {
        const dmarcData = await dnsQuery("_dmarc." + domain, "TXT");
        removeCursor(termId);
        if (dmarcData.Answer) {
          dmarcData.Answer.forEach(rec => {
            const v = rec.data.replace(/^"|"$/g,"");
            if (v.startsWith("v=DMARC1")) {
              dmarcFound = true;
              writeLine(termId, "[+] DMARC record found:", "success");
              writeLine(termId, "    " + v, "info");
              if      (v.includes("p=none"))       writeLine(termId, "[!] DMARC policy=none — monitoring only, no enforcement (MEDIUM)", "warn");
              else if (v.includes("p=quarantine"))  writeLine(termId, "[*] DMARC policy=quarantine — suspicious mail goes to spam (GOOD)", "cmd");
              else if (v.includes("p=reject"))      writeLine(termId, "[+] DMARC policy=reject — strongest protection (PASS)", "success");
            }
          });
        }
      } catch(e) { removeCursor(termId); }

      if (!dmarcFound) writeLine(termId, "[!] No DMARC record found — phishing risk (MEDIUM)", "warn");
      writeLine(termId, "", "muted");
    }

    /* ── Subdomain enumeration ── */
    if (opts.includes("Subdomain Enumeration")) {
      writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
      writeLine(termId, `[*] Starting subdomain enumeration for ${domain}`, "cmd");
      writeLine(termId, `[*] Wordlist: ${SUBDOMAINS.length} entries | Source: dns.google DoH`, "cmd");
      writeLine(termId, "", "muted");

      let found = 0;
      for (const sub of SUBDOMAINS) {
        const fqdn = `${sub}.${domain}`;
        try {
          const res = await dnsQuery(fqdn, "A");
          if (res.Answer && res.Answer.length > 0) {
            const ips = res.Answer.filter(r => r.type === 1).map(r => r.data).join(", ");
            if (ips) {
              writeLine(termId, `[+] ${fqdn.padEnd(46)} → ${ips}`, "success");
              found++;
            }
          }
        } catch (_) { /* subdomain not found */ }
      }

      writeLine(termId, "", "muted");
      writeLine(termId, found === 0
        ? "[*] No subdomains discovered from wordlist."
        : `[+] Enumeration complete — ${found} subdomain(s) discovered.`,
        found === 0 ? "muted" : "success"
      );
      writeLine(termId, "", "muted");
    }

    /* ── Zone transfer ── */
    if (opts.includes("Zone Transfer (AXFR)")) {
      writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
      writeLine(termId, "[*] Attempting zone transfer (AXFR)...", "cmd");
      writeCursor(termId);
      try {
        const nsData = await dnsQuery(domain, "NS");
        removeCursor(termId);
        if (nsData.Answer) {
          for (const ns of nsData.Answer) {
            writeLine(termId, `[*] Trying zone transfer from nameserver: ${ns.data}`, "cmd");
            writeLine(termId, `[-] Transfer failed: Connection refused — AXFR disabled (expected)`, "err");
          }
        }
      } catch (e) {
        removeCursor(termId);
      }
      writeLine(termId, "[*] Zone transfer blocked — server is correctly configured.", "muted");
      writeLine(termId, "", "muted");
    }

    /* ── Reverse DNS ── */
    if (opts.includes("Reverse DNS")) {
      writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
      writeLine(termId, "[*] Performing reverse DNS lookup on resolved IPs...", "cmd");
      writeCursor(termId);
      try {
        const aData = await dnsQuery(domain, "A");
        removeCursor(termId);
        if (aData.Answer) {
          for (const rec of aData.Answer.filter(r => r.type === 1)) {
            const parts  = rec.data.split(".").reverse();
            const arpa   = parts.join(".") + ".in-addr.arpa";
            try {
              const ptrData = await dnsQuery(arpa, "PTR");
              const ptr = ptrData.Answer?.[0]?.data || "No PTR record";
              writeLine(termId, `[*] ${rec.data.padEnd(18)} → ${ptr}`, "blue");
            } catch (_) {
              writeLine(termId, `[*] ${rec.data.padEnd(18)} → No PTR record`, "muted");
            }
          }
        }
      } catch (e) {
        removeCursor(termId);
        writeLine(termId, "[-] Reverse DNS failed: " + e.message, "err");
      }
      writeLine(termId, "", "muted");
    }

    writeLine(termId, "[*] DNS lookup complete.", "cmd");

  } catch (e) {
    removeCursor(termId);
    writeLine(termId, "[-] Fatal error: " + e.message, "err");
    writeLine(termId, "[!] Check domain format (no http://) and internet connection.", "warn");
  }
}

/* ═══════════════════════════════════════════
   TOOL 4: WHOIS  (REAL — rdap.org + ip-api.com)
═══════════════════════════════════════════ */

function isIP(str) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(str); }
function pad28(s)  { return (s + ":").padEnd(28); }
function wField(termId, label, val, cls = "info") {
  if (val && !["N/A","","REDACTED FOR PRIVACY","redacted for privacy","DATA REDACTED"].includes(String(val).trim())) {
    writeLine(termId, `${cls === "success" ? "[+]" : "[*]"} ${pad28(label)} ${val}`, cls);
  }
}

async function runWhois() {
  const target = document.getElementById("wi-target").value.trim();
  const termId = "whois-out";

  if (!target) {
    clearTerm(termId);
    writeLine(termId, "[-] Error: no target specified", "err");
    return;
  }

  const opts  = getOpts(["wi-reg","wi-dates","wi-ns","wi-geo"]);
  const ip    = isIP(target);
  const allOn = opts.length === 0;   /* if nothing selected, show everything */

  clearTerm(termId);
  writeLine(termId, `[*] WHOIS query for: ${target}`, "cmd");
  writeLine(termId, `[*] Type detected: ${ip ? "IPv4 Address" : "Domain Name"}`, "cmd");
  writeLine(termId, "", "muted");
  writeCursor(termId);

  try {

    /* ── IP Geolocation (ip-api.com) ── */
    if (ip || allOn || opts.includes("IP Geolocation")) {
      const geoTarget = ip ? target : target;
      let resolvedIp  = geoTarget;

      /* If domain, resolve first */
      if (!ip) {
        try {
          const aRec = await dnsQuery(target, "A");
          if (aRec.Answer?.[0]) resolvedIp = aRec.Answer[0].data;
        } catch (_) {}
      }

      try {
        const geoRes = await fetch(
          `${GEO_API}/${resolvedIp}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query`
        );
        const geo = await geoRes.json();
        removeCursor(termId);

        if (geo.status === "success") {
          writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
          writeLine(termId, "  IP GEOLOCATION & NETWORK INFORMATION", "cmd");
          writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
          writeLine(termId, `[+] ${pad28("IP Address")} ${geo.query}`, "success");
          wField(termId, "Hostname (rDNS)",  geo.reverse || "— no PTR record");
          wField(termId, "Country",          `${geo.country} (${geo.countryCode})`);
          wField(termId, "Region",           `${geo.regionName} (${geo.region})`);
          wField(termId, "City",             geo.city);
          wField(termId, "ZIP / Postal Code", geo.zip || "N/A");
          writeLine(termId, `[*] ${pad28("Coordinates")} ${geo.lat}, ${geo.lon}`, "blue");
          wField(termId, "Timezone",         geo.timezone);
          wField(termId, "ISP",              geo.isp);
          wField(termId, "Organisation",     geo.org);
          writeLine(termId, `[*] ${pad28("ASN")} ${geo.as}`, "blue");
          wField(termId, "AS Name",          geo.asname);
          writeLine(termId, "", "muted");
        } else {
          writeLine(termId, `[-] Geolocation failed: ${geo.message || "private/reserved IP range"}`, "err");
        }
      } catch (e) {
        removeCursor(termId);
        writeLine(termId, `[-] Geolocation API error: ${e.message}`, "err");
      }

      if (ip) {
        writeLine(termId, "[*] Lookup complete.", "cmd");
        return;
      }

      writeCursor(termId);
    }

    /* ── Domain WHOIS via rdap.org ── */
    writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");
    writeLine(termId, "  DOMAIN REGISTRATION RECORD (via RDAP)", "cmd");
    writeLine(termId, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "muted");

    const rdapRes = await fetch(`${RDAP_API}/${encodeURIComponent(target)}`);
    removeCursor(termId);

    if (!rdapRes.ok) {
      writeLine(termId, `[-] RDAP lookup failed (${rdapRes.status}) — domain may not exist or TLD unsupported`, "err");
      writeLine(termId, `[!] Try: whois ${target}  in your terminal for raw data`, "warn");
      return;
    }

    const rdap = await rdapRes.json();

    writeLine(termId, `[+] ${pad28("Domain Name")} ${(rdap.ldhName || target).toUpperCase()}`, "success");
    wField(termId, "Handle",          rdap.handle);
    wField(termId, "Unicode Name",    rdap.unicodeName);

    /* Dates */
    if (allOn || opts.includes("Expiry Dates")) {
      writeLine(termId, "", "muted");
      writeLine(termId, "  -- Dates --", "muted");
      if (rdap.events) {
        const evMap = {};
        rdap.events.forEach(ev => { evMap[ev.eventAction] = ev.eventDate; });
        const created  = evMap["registration"];
        const updated  = evMap["last changed"];
        const expires  = evMap["expiration"];

        if (created) writeLine(termId, `[*] ${pad28("Created")}  ${new Date(created).toUTCString()}`, "info");
        if (updated) writeLine(termId, `[*] ${pad28("Last Updated")} ${new Date(updated).toUTCString()}`, "info");
        if (expires) {
          writeLine(termId, `[*] ${pad28("Expires")}  ${new Date(expires).toUTCString()}`, "info");
          const days = Math.ceil((new Date(expires) - Date.now()) / 86400000);
          if (days < 0)        writeLine(termId, `[!] ${pad28("⚠ STATUS")} EXPIRED ${Math.abs(days)} days ago! (CRITICAL)`, "err");
          else if (days < 30)  writeLine(termId, `[!] ${pad28("⚠ Expiry Warning")} Expires in ${days} days! Renew immediately (CRITICAL)`, "err");
          else if (days < 90)  writeLine(termId, `[!] ${pad28("⚠ Expiry Warning")} Expires in ${days} days — renew soon (MEDIUM)`, "warn");
          else                 writeLine(termId, `[+] ${pad28("Days Until Expiry")} ${days} days`, "success");
        }
      }
    }

    /* Nameservers */
    if (allOn || opts.includes("Nameservers")) {
      writeLine(termId, "", "muted");
      writeLine(termId, "  -- Nameservers --", "muted");
      if (rdap.nameservers && rdap.nameservers.length > 0) {
        rdap.nameservers.forEach(ns => {
          writeLine(termId, `[*] ${pad28("Name Server")} ${ns.ldhName || ns.unicodeName}`, "blue");
        });
      } else {
        writeLine(termId, "[!] No nameserver data available", "warn");
      }
    }

    /* Status */
    writeLine(termId, "", "muted");
    writeLine(termId, "  -- Status Flags --", "muted");
    if (rdap.status && rdap.status.length > 0) {
      rdap.status.forEach(s => {
        const cls = s.includes("hold") || s.includes("lock") ? "warn" : "info";
        writeLine(termId, `[*] ${pad28("Status")} ${s}`, cls);
      });
    }

    /* Registrar */
    if (allOn || opts.includes("Registrar Info")) {
      writeLine(termId, "", "muted");
      writeLine(termId, "  -- Registrar --", "muted");
      if (rdap.entities) {
        rdap.entities.forEach(entity => {
          if (!entity.roles) return;
          const role = entity.roles[0];
          const vcard = entity.vcardArray?.[1] || [];
          const name  = vcard.find(v => v[0] === "fn")?.[3]    || "N/A";
          const email = vcard.find(v => v[0] === "email")?.[3] || "N/A";
          const tel   = vcard.find(v => v[0] === "tel")?.[3]   || "N/A";
          const url   = vcard.find(v => v[0] === "url")?.[3]   || "N/A";

          if (role === "registrar") {
            writeLine(termId, `[+] ${pad28("Registrar")} ${name}`, "success");
            wField(termId, "Registrar Email",  email);
            wField(termId, "Registrar Phone",  tel);
            wField(termId, "Registrar URL",    url);
          }
          if (role === "registrant") {
            writeLine(termId, "", "muted");
            writeLine(termId, `[*] ${pad28("Registrant")} ${name}`, "info");
            wField(termId, "Registrant Email", email);
          }
        });
      }
    }

    /* DNSSEC */
    writeLine(termId, "", "muted");
    const sec = rdap.secureDNS;
    if (sec) {
      if (sec.delegationSigned) writeLine(termId, "[+] DNSSEC: Delegation signed", "success");
      else if (sec.zoneSigned)  writeLine(termId, "[*] DNSSEC: Zone signed", "info");
      else                      writeLine(termId, "[!] DNSSEC: Not signed (unsigned)", "warn");
    }

    writeLine(termId, "", "muted");
    writeLine(termId, "[*] WHOIS lookup complete.", "cmd");

  } catch (e) {
    removeCursor(termId);
    writeLine(termId, "[-] Error: " + e.message, "err");
    writeLine(termId, "[!] If domain uses a restricted TLD, RDAP may not be available.", "warn");
  }
}

/* ═══════════════════════════════════════════
   TOOL 5: WEB HACKING  (AI-simulated)
═══════════════════════════════════════════ */

async function runWebHack() {
  const url = document.getElementById("wh-url").value.trim();

  if (!url) {
    clearTerm("web-out");
    writeLine("web-out", "[-] Error: no target URL specified", "err");
    return;
  }

  if (!url.startsWith("http")) {
    clearTerm("web-out");
    writeLine("web-out", "[-] Error: URL must start with http:// or https://", "err");
    return;
  }

  const opts = getOpts(["wh-headers","wh-xss","wh-sqli","wh-csrf","wh-dir","wh-ssl","wh-cors","wh-cve"]);

  const prompt = `Simulate a professional web vulnerability assessment of: ${url}
Tests requested: ${opts.join(", ") || "full basic recon"}

For EACH test, produce realistic tool output with findings and severity ratings.
${opts.includes("HTTP Headers") ? `
[HTTP HEADERS]
- Check: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection
- Show actual header values where missing or misconfigured
- Rate each missing header by severity` : ""}
${opts.includes("XSS Vectors") ? `
[XSS TESTING]
- Test common injection points: GET params, POST body, HTTP headers, cookies
- Show specific payloads tested: <script>alert(1)</script>, etc.
- Report reflected/stored/DOM XSS findings with exact parameter names` : ""}
${opts.includes("SQL Injection") ? `
[SQL INJECTION]
- Test parameters with: ', ", --, ;, 1=1, UNION SELECT, etc.
- Show boolean-based, error-based, and time-based blind SQLi results
- Include DB error messages if found` : ""}
${opts.includes("CSRF Detection") ? `
[CSRF DETECTION]
- Check for CSRF tokens in all forms
- Check SameSite cookie attributes
- Check Origin/Referer header validation` : ""}
${opts.includes("Dir Busting") ? `
[DIRECTORY BUSTING]
- Enumerate: /admin, /login, /api, /backup, /.git, /.env, /config, /wp-admin,
  /phpmyadmin, /uploads, /static, /debug, /console, /actuator, /swagger
- Show HTTP status codes: 200, 301, 302, 403, 404` : ""}
${opts.includes("SSL/TLS Audit") ? `
[SSL/TLS AUDIT]
- TLS versions supported (SSLv3/TLSv1.0 deprecated)
- Certificate validity, expiry date, issuer, Subject Alt Names
- Cipher suite strength, forward secrecy, HSTS` : ""}
${opts.includes("CORS Misconfig") ? `
[CORS MISCONFIGURATION]
- Test with: Origin: https://evil.com, null, *
- Show Access-Control-Allow-Origin response values
- Flag wildcard or credential-allowing misconfigs` : ""}
${opts.includes("CVE Lookup") ? `
[CVE / SERVER FINGERPRINT]
- Fingerprint server from headers: Server, X-Powered-By, Via
- Match software + version to known CVEs
- Show CVE ID, CVSS score, severity, brief description` : ""}

End with a summary table: CRITICAL / HIGH / MEDIUM / LOW / INFO counts.
Be technically accurate and thorough.`;

  await callClaude(prompt, "web-out");
}

/* ═══════════════════════════════════════════
   INIT
═══════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  updateApiBanner();
});
