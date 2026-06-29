/* ============== SOURCES ============== */
const sources = {
    ipv4: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}"},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}"},
        {name:"ThreatFox", url:"https://threatfox.abuse.ch/browse.php?search=ioc%3A{data}", usesDomain:false, encode:false},
        {name:"AnyRun (Search)", url:"https://intelligence.any.run/analysis/lookup#{%22query%22:%22{data}%22,%22dateRange%22:180}"},
        {name:"Guardpot", url:"https://threatsummary.guardpot.com/{data}"},
        {name:"MXToolBox (Blacklist)", url:"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{data}&run=toolpage#", usesDomain:false, encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"CleanTalk (Blacklist)", url:"https://cleantalk.org/blacklists/{data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"},
        {name:"IPinfo", url:"https://ipinfo.io/{data}"},
        {name:"WhatIsMyIPAddress", url:"https://whatismyipaddress.com/ip/{data}"},
        {name:"MyIP", url:"https://myip.ms/info/whois/{data}"},
        {name:"SPUR (detect VPNs)", url:"https://spur.us/context/{data}"},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
        {name:"RIPEstat (Database)", url:"https://stat.ripe.net/resource/{data}#tab=database"},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    ipv6: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/browse/global/pulses?q={data}"},
        {name:"AnyRun (Search)", url:"https://intelligence.any.run/analysis/lookup#{%22query%22:%22{data}%22,%22dateRange%22:180}"},
        {name:"MXToolBox (Blacklist)", url:"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{data}&run=toolpage#", usesDomain:false, encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"CleanTalk (Blacklist)", url:"https://cleantalk.org/blacklists/{data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"},
        {name:"IPinfo", url:"https://ipinfo.io/{data}"},
        {name:"WhatIsMyIPAddress", url:"https://whatismyipaddress.com/ip/{data}"},
        {name:"MyIP", url:"https://myip.ms/info/whois/{data}"},
        {name:"SPUR (detect VPNs)", url:"https://spur.us/context/{data}"},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
        {name:"RIPEstat (Database)", url:"https://stat.ripe.net/resource/{data}#tab=database"},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    url: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/url/{data}", needsHash:true, encode:true},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/url/{data}",encode:false},
        {name:"URLScan", url:"https://urlscan.io/search/#page.domain:{data}", encode:false, usesDomain:true, noWWW:true},
        {name:"MXToolBox (Blacklist)", url:"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{data}&run=toolpage#", usesDomain:true, encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"CleanTalk (Blacklist)", url:"https://cleantalk.org/blacklists/{data}", usesDomain:true, encode:false},
        {name:"CleanTalk (Malware Scan)", url:"https://cleantalk.org/website-malware-scanner?url={data}", usesDomain:false, encode:false},
        {name:"SUCURI (Malware Scan)", url:"https://sitecheck.sucuri.net/results/{data}", usesDomain:false, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", usesDomain:true, noWWW:true},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}",encode:false},
        {name:"ThreatFox", url:"https://threatfox.abuse.ch/browse.php?search=ioc%3A{data}", usesDomain:true, encode:false},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}", usesDomain:true},
        {name:"DNSLytics", url:"https://search.dnslytics.com/search?q={data}&d=%3Call%3E", usesDomain:true},
        {name:"Netcraft", url:"https://sitereport.netcraft.com/?url={data}"},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}"},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}", usesDomain:true},
        {name:"Hudson Rock Infostealer", url:"https://www.hudsonrock.com/search/domain/{data}", usesDomain:true, noWWW:true},
        {name:"Hudson Rock (URL Discovery)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={data}", usesDomain:true, noWWW:true},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:true, noWWW:true},
        {name:"Wayback Machine", url:"https://web.archive.org/web/{data}"},
        {name:"Wayback Machine (Save)", url:"https://web.archive.org/save/{data}"},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false},
        {name:"AnyRun (Search)", url:"https://intelligence.any.run/analysis/lookup#{%22query%22:%22{data}%22,%22dateRange%22:180}"},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}", usesDomain:true},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    domain: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/domain/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/domain/{data}"},
        {name:"URLScan", url:"https://urlscan.io/search/#page.domain:{data}", encode:false, usesDomain:true, noWWW:true},
        {name:"MXToolBox (Blacklist)", url:"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{data}&run=toolpage#", usesDomain:false, encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"CleanTalk (Blacklist)", url:"https://cleantalk.org/blacklists/{data}", usesDomain:false, encode:false},
        {name:"CleanTalk (Malware Scan)", url:"https://cleantalk.org/website-malware-scanner?url={data}", usesDomain:false, encode:false},
        {name:"SUCURI (Malware Scan)", url:"https://sitecheck.sucuri.net/results/{data}", usesDomain:false, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", noWWW:true},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}"},
        {name:"ThreatFox", url:"https://threatfox.abuse.ch/browse.php?search=ioc%3A{data}", usesDomain:true, encode:false},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}"},
        {name:"DNSLytics", url:"https://search.dnslytics.com/search?q={data}&d=%3Call%3E", usesDomain:true},
        {name:"Netcraft", url:"https://sitereport.netcraft.com/?url={data}"},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}"},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}"},
        {name:"HudsonRock Infostealer", url:"https://www.hudsonrock.com/search/domain/{data}", usesDomain:true, noWWW:true},
        {name:"HudsonRock (URL Discovery)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={data}", usesDomain:true, noWWW:true},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:true, noWWW:true},
        {name:"Wayback Machine", url:"https://web.archive.org/web/{data}"},
        {name:"Wayback Machine (Save)", url:"https://web.archive.org/save/{data}"},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false},
        {name:"AnyRun (Search)", url:"https://intelligence.any.run/analysis/lookup#{%22query%22:%22{data}%22,%22dateRange%22:180}"},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    hash: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/file/{data}"},
        {name:"Hybrid-Analysis", url:"https://www.hybrid-analysis.com/sample/{data}"},
        {name:"JOE Sandbox", url:"https://www.joesandbox.com/analysis/search?q={data}"},
        {name:"Triage", url:"https://tria.ge/s?q={data}"},
        {name:"MalShare", url:"https://malshare.com/sample.php?action=detail&hash={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/malware/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/talos_file_reputation?s={data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/file/{data}"},
        {name:"AnyRun (Search)", url:"https://intelligence.any.run/analysis/lookup#{%22query%22:%22{data}%22,%22dateRange%22:180}"},
        {name:"Threat.Rip", url:"https://www.threat.rip/search?q=hash%253A{data}"},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}"},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    email: [
        {name:"Have I Been Pwned", url:"https://haveibeenpwned.com/unifiedsearch/{data}", usesDomain:false, encode:false},
        {name:"HudsonRock Infostealer", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={data}", usesDomain:false, encode:false},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:false},
        {name:"Intelbase", url:"https://intelbase.is/"},
        {name:"IntelX", url:"https://intelx.io/?s={data}&b=leaks.public.wikileaks,leaks.public.general,dumpster,documents.public.scihub", encode:false},
        {name:"Internxt DarkWeb Monitor", url:"https://internxt.com/dark-web-monitor", encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
    ],
    text: [
        {name:"Google", url:"https://www.google.com/search?q={data}"},
        {name:"Translate", url:"https://translate.google.com/?sl=auto&tl=en&text={data}&op=translate"},
        {name:"LOLBAS", url:"https://lolbas-project.github.io/#{data}", encode:false},
        {name:"GTFOBins", url:"https://gtfobins.github.io/#{data}", encode:false},
        {name:"LOTS Project", url:"https://lots-project.com/", encode:false},
        {name:"MalAPI", url:"https://malapi.io/", encode:false},
        {name:"FILESEC", url:"https://filesec.io/", encode:false},
        {name:"xCyclopedia", url:"https://www.google.com/search?q=inurl:strontic.github.io/xcyclopedia+{data}"},
        {name:"Mitre", url:"https://www.google.com/search?q=inurl:attack.mitre.org+{data}"},
        {name:"NIST NVD", url:"https://nvd.nist.gov/vuln/search#/nvd/home?keyword={data}&resultType=records"},
        {name:"CVE ORG", url:"https://www.cve.org/CVERecord?id={data}"},
        {name:"CVE RADAR", url:"https://socradar.io/labs/app/cve-radar/{data}"},
        {name:"Exploit DB", url:"https://www.exploit-db.com/search?q={data}"},
        {name:"Windows EventID", url:"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={data}"},
        {name:"Microsoft ErrorCode", url:"https://login.microsoftonline.com/error?code={data}", encode:false},
        {name:"HudsonRock Infostealer (Username)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={data}", usesDomain:false},
        {name:"Nitter (Tweets)", url:"https://nitter.net/search?f=tweets&q={data}&since=&until=&min_faves="},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
        {name:"WikiLeaks", url:"https://search.wikileaks.org/?query={data}", encode:false},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
        {name:"ExplainShell", url:"https://explainshell.com/explain?cmd={data}", encode:false, base64:false},
        {name:"Port Info", url:"https://speedguide.net/port.php?port={data}", encode:false, base64:false},
        {name:"MXToolBox - EmailHeaders", url:"https://mxtoolbox.com/EmailHeaders.aspx", encode:false},
        {name:"Threat Encyclopedia", url:"https://www.trendmicro.com/vinfo/us/threat-encyclopedia/search/{data}", encode:false, base64:false},
        {name:"Valhalla (SIGMA/YARA Rules)", url:"https://valhalla.nextron-systems.com/info/search?keyword={data}", encode:false, base64:false},
        {name:"Ransomware.Live", url:"https://www.ransomware.live/search?q={data}&scope=all"},
        {name:"No More Ransom", url:"https://www.nomoreransom.org/crypto-sheriff.php"},
    ]
};

/* ================= DEFANG ================= */
function normalizeDefang(v) {
    return v
        // hxxps:// / hxxp:// → https:// / http://
        .replace(/^hxxps?:\/\//i, m => m.toLowerCase().replace("hxxp", "http"))
        // http[s]:// → https://  (defanged scheme bracket)
        .replace(/^http\[s\]:\/\//i, "https://")
        // h**ps:// or h**p://
        .replace(/^h\*\*ps?:\/\//i, m => m.replace("**", "tt"))
        // [.] (.) {.} → .
        .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
        // IPv6 defang: [::] → ::  and  [:] → :
        .replace(/\[::\]/g, "::")
        .replace(/\[:\]/g, ":")
        .trim();
}

function defangValue(v, type) {
    switch (type) {
        case "ipv4":
            return v.replace(/\./g, "[.]");
        case "ipv6":
            // Replace single : first, then restore [:][:] back to [::]
            return v.replace(/:/g, "[:]").replace(/\[:\]\[:\]/g, "[::]");
        case "url":
            return v
                .replace(/^https?:\/\//i, m => m.toLowerCase().replace("http", "hxxp"))
                .replace(/\./g, "[.]");
        case "domain":
            return v.replace(/\./g, "[.]");
        default:
            return v;
    }
}

/* ============== DETECTORS ============== */
function isIPv4(i) {
    return /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(i);
}

// FIX: support all IPv6 forms — abbreviated (::), full 8-group, and defanged variants.
// URL constructor normalizes IPv6 (e.g. compresses consecutive zeros), so we can't
// compare hostname === input. We just check that it parses without throwing.
function isIPv6(i) {
    try {
        new URL(`http://[${i}]`);
        return true;
    } catch {
        return false;
    }
}

function isURL(i) { return /^https?:\/\/[^\s]+$/.test(i); }
function isDomain(i) { return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(i); }
function isHash(i) { return /^[a-fA-F0-9]{32,128}$/.test(i); }
function isEmail(i) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(i); }

function detectType(input) {
    if (isIPv4(input))  return "ipv4";
    if (isIPv6(input))  return "ipv6";
    if (isURL(input))   return "url";
    if (isEmail(input)) return "email";
    if (isHash(input))  return "hash";   // FIX: hash before domain to avoid false positives
    if (isDomain(input)) return "domain";
    return "text";
}

/* ================= UTILITIES ================= */
function emailDomain(email) { return email.split("@")[1].toLowerCase(); }
function urlDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

async function sha256(input) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// FIX: replaced deprecated unescape() with a standards-compliant implementation
function toBase64(str) {
    return btoa(
        encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
            (_, p1) => String.fromCharCode(parseInt(p1, 16)))
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

/* ================= NORMALIZATION ================= */

// Normalize URL to match VirusTotal's canonical form:
// VT always adds a trailing slash if there's no path, query or fragment.
// e.g. http://soctoolkit.com → http://soctoolkit.com/
function normalizeUrlForHashing(url) {
    try {
        const u = new URL(url);
        // Only add slash if path is empty (just the origin)
        if (u.pathname === "" || u.pathname === "/") {
            u.pathname = "/";
        }
        return u.href;
    } catch {
        return url; // fallback: return as-is if URL is unparseable
    }
}

async function prepareData(input, type, src) {
    let data = input;

    if (type === "url" && src.needsHash) {
        data = await sha256(normalizeUrlForHashing(input));
    }

    if (src.usesDomain) {
        if (type === "email") {
            data = emailDomain(input);
        } else if (type === "url" || type === "domain") {
            data = urlDomain(input);
        }
    }

    if (src.noWWW) {
        data = data.replace(/^www\./i, "");
    }

    if (src.base64 === true) {
        data = toBase64(data);
        return data;
    } else if (src.encode !== false) {
        data = encodeURIComponent(data);
    }

    return data;
}

/* ================= MULTI-IOC PARSER ================= */
function parseMultipleIoCs(raw) {
    return raw
        .split(/[\n,]+/)          // split by newline or comma
        .map(s => s.trim())
        .filter(Boolean)
        .map(normalizeDefang)
        .filter(Boolean);
}

/* ================= FAVORITES / UNLOCK PREFERENCES ================= */
const OPEN_PREF_KEY = "soc_openall_preferences";

function loadOpenPrefs() {
    try { return JSON.parse(localStorage.getItem(OPEN_PREF_KEY) || "{}"); } catch { return {}; }
}

function saveOpenPrefs(prefs) {
    localStorage.setItem(OPEN_PREF_KEY, JSON.stringify(prefs));
}

function isUnlocked(type, name) {
    const prefs = loadOpenPrefs();
    return prefs[`${type}|${name}`] === true;
}

function toggleUnlocked(type, name) {
    const prefs = loadOpenPrefs();
    const key = `${type}|${name}`;
    prefs[key] = !prefs[key];
    saveOpenPrefs(prefs);
    return prefs[key];
}

/* ================= CARD ORDER PERSISTENCE ================= */
const ORDER_KEY = "soc_card_order";

function loadOrder(type) {
    try {
        const saved = JSON.parse(localStorage.getItem(ORDER_KEY) || "{}");
        return saved[type] || null; // null = use default source order
    } catch { return null; }
}

function saveOrder(type, nameArray) {
    try {
        const saved = JSON.parse(localStorage.getItem(ORDER_KEY) || "{}");
        saved[type] = nameArray;
        localStorage.setItem(ORDER_KEY, JSON.stringify(saved));
    } catch {}
}

// Returns sources[type] + custom tools, reordered to match saved order
function getOrderedSources(type) {
    const native  = sources[type] || [];
    const custom  = getCustomToolsForType(type).map(t => ({ ...t, custom: true }));
    const list    = [...native, ...custom];
    const saved   = loadOrder(type);
    if (!saved) return list;

    const byName  = Object.fromEntries(list.map(s => [s.name, s]));
    const ordered = saved.map(n => byName[n]).filter(Boolean);

    // Append any new sources not yet in saved order
    const savedSet = new Set(saved);
    list.forEach(s => { if (!savedSet.has(s.name)) ordered.push(s); });

    return ordered;
}

/* ================= DOM REFERENCES ================= */
// FIX: explicit declarations instead of implicit global references
const lookupBtn      = document.getElementById("lookupBtn");
const inputData      = document.getElementById("inputData");
const openUnlocked   = document.getElementById("openAll");
const results        = document.getElementById("results");
const normalValue    = document.getElementById("normalValue");
const defangedValue  = document.getElementById("defangedValue");
const normalizedInfo = document.getElementById("normalizedInfo");

/* ================= RENDER ================= */
// Safe helper: sets label + clickable text without innerHTML injection risk
function setCopiableValue(containerId, label, value) {
    const container = document.getElementById(containerId);
    container.textContent = "";

    const strong = document.createElement("strong");
    strong.textContent = label;

    const span = document.createElement("span");
    span.textContent = value;
    span.style.cursor = "pointer";

    span.onclick = () => {
        navigator.clipboard.writeText(value);
        const orig = span.textContent;
        span.textContent = "Copied!";
        setTimeout(() => span.textContent = orig, 1000);
    };

    container.appendChild(strong);
    container.appendChild(document.createTextNode(" "));
    container.appendChild(span);
}

async function renderLinks(raw) {
    if (!raw) return;

    const iocs = parseMultipleIoCs(raw);
    if (!iocs.length) return;

    const type = detectType(iocs[0]);

    results.innerHTML = "";

    // ── Normalized / Defanged info for each IoC ──
    const showDefang = ["ipv4", "ipv6", "url", "domain"].includes(type);
    const showTable  = showDefang || ["email", "hash"].includes(type);
    normalizedInfo.innerHTML = "";

    if (showTable) {
        const table = document.createElement("div");
        table.className = "ioc-table";

        // Header — type label; defang column only when applicable
        const typeLabel = { ipv4: "IPv4", ipv6: "IPv6", url: "URL", domain: "Domain", email: "Email", hash: "Hash" }[type];
        const header = document.createElement("div");
        header.className = "ioc-row ioc-header" + (showDefang ? "" : " ioc-row-single");
        const headerCols = showDefang ? ["#", typeLabel, "Defanged"] : ["#", typeLabel];
        headerCols.forEach((h, colIdx) => {
            const cell = document.createElement("span");
            cell.textContent = h;

            // Columns 1 (type) and 2 (defanged) copy all values on click
            if (colIdx === 1) {
                cell.className = "ioc-header-copy";
                cell.title = `Copy all ${h} values`;
                cell.onclick = () => {
                    navigator.clipboard.writeText(iocs.join("\n"));
                    const orig = cell.textContent;
                    cell.textContent = "Copied!";
                    setTimeout(() => cell.textContent = orig, 1000);
                };
            } else if (colIdx === 2 && showDefang) {
                cell.className = "ioc-header-copy";
                cell.title = "Copy all Defanged values";
                cell.onclick = () => {
                    navigator.clipboard.writeText(iocs.map(ioc => defangValue(ioc, type)).join("\n"));
                    const orig = cell.textContent;
                    cell.textContent = "Copied!";
                    setTimeout(() => cell.textContent = orig, 1000);
                };
            }

            header.appendChild(cell);
        });
        table.appendChild(header);

        // One row per IoC
        iocs.forEach((ioc, i) => {
            const row = document.createElement("div");
            row.className = "ioc-row" + (showDefang ? "" : " ioc-row-single");

            const idxCell = document.createElement("span");
            idxCell.textContent = i + 1;
            idxCell.className = "ioc-index";

            const normalCell = document.createElement("span");
            normalCell.textContent = ioc;
            normalCell.className = "ioc-copy";
            normalCell.title = "Click to copy";
            normalCell.onclick = () => {
                navigator.clipboard.writeText(ioc);
                const orig = normalCell.textContent;
                normalCell.textContent = "Copied!";
                setTimeout(() => normalCell.textContent = orig, 1000);
            };

            row.appendChild(idxCell);
            row.appendChild(normalCell);

            if (showDefang) {
                const defanged = defangValue(ioc, type);
                const defangCell = document.createElement("span");
                defangCell.textContent = defanged;
                defangCell.className = "ioc-copy";
                defangCell.title = "Click to copy";
                defangCell.onclick = () => {
                    navigator.clipboard.writeText(defanged);
                    const orig = defangCell.textContent;
                    defangCell.textContent = "Copied!";
                    setTimeout(() => defangCell.textContent = orig, 1000);
                };
                row.appendChild(defangCell);
            }

            table.appendChild(row);
        });

        normalizedInfo.appendChild(table);
        normalizedInfo.style.display = "block";
    } else {
        normalizedInfo.style.display = "none";
    }

    // ── Render one card per service ──
    for (const src of getOrderedSources(type)) {

        // Build all links for this source (one per IoC), validate each
        const links = [];
        for (const ioc of iocs) {
            const p       = await prepareData(ioc, type, src);
            const rawLink = src.url.replace("{data}", p);
            const lower   = rawLink.toLowerCase();
            if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
                console.warn("Blocked non-http URL:", rawLink);
                continue;
            }
            links.push(rawLink);
        }

        if (!links.length) continue;

        // Use first link for favicon + href (single IoC keeps original behaviour)
        const firstLink = links[0];
        let domain = "";
        try { domain = new URL(firstLink).hostname; } catch {}

        const unlocked = isUnlocked(type, src.name);
        const lockIcon = unlocked ? "🔓" : "🔒";

        const a = document.createElement("a");
        // Single IoC → normal link; multiple → prevent default and open all
        if (iocs.length === 1) {
            a.href   = firstLink;
            a.target = "_blank";
            a.rel    = "noopener noreferrer";
        } else {
            a.href = "#";
            a.addEventListener("click", (e) => {
                if (e.target.classList.contains("lock-btn")) return;
                e.preventDefault();
                links.forEach(url => window.open(url, "_blank"));
            });
        }
        a.className = "link-card";

        const img = document.createElement("img");
        img.src = `https://www.google.com/s2/favicons?domain=${domain}`;
        img.alt = src.name;

        const titleDiv = document.createElement("div");
        titleDiv.className = "title";

        const nameSpan = document.createElement("span");
        nameSpan.textContent = src.name;

        // Badge showing how many tabs will open (only for multi-IoC)
        if (iocs.length > 1) {
            const badge = document.createElement("span");
            badge.className = "ioc-count-badge";
            badge.textContent = `×${iocs.length}`;
            badge.title = `Opens ${iocs.length} tabs`;
            nameSpan.appendChild(badge);
        }

        const lockBtn = document.createElement("span");
        lockBtn.className    = "lock-btn";
        lockBtn.textContent  = lockIcon;
        lockBtn.title        = unlocked ? "Remove from unlocked" : "Unlock to open with 'Open Unlocked'";
        lockBtn.dataset.type = type;
        lockBtn.dataset.name = src.name;

        titleDiv.appendChild(img);
        titleDiv.appendChild(nameSpan);

        // Delete button for custom tools — inside titleDiv, left of favicon
        if (src.custom) {
            const delBtn = document.createElement("span");
            delBtn.className   = "delete-tool-btn";
            delBtn.textContent = "❌";
            delBtn.title       = "Remove custom tool";
            delBtn.onclick     = (e) => {
                e.preventDefault();
                e.stopPropagation();
                const allTypes = ["ipv4","ipv6","domain","url","hash","email","text"];
                allTypes.forEach(t => deleteCustomTool(t, src.name));
                renderLinks(inputData.value.trim());
                showToast(`"${src.name}" removed.`);
            };
            titleDiv.insertBefore(delBtn, img);
        }

        const urlSpan = document.createElement("span");
        urlSpan.className   = "url";
        urlSpan.textContent = iocs.length > 1 ? `${iocs.length} IoCs → ${src.name}` : firstLink;

        // Mobile drag handle — positioned bottom-right of card
        const dragHandle = document.createElement("span");
        dragHandle.className   = "drag-handle";
        dragHandle.textContent = "⠿";
        dragHandle.title       = "Drag to reorder";

        a.appendChild(titleDiv);
        a.appendChild(urlSpan);
        a.appendChild(dragHandle);

        // Wrapper so lockBtn sits outside <a> but stays visually on the card
        const wrapper = document.createElement("div");
        wrapper.className = "card-wrapper";
        wrapper.dataset.name = src.name;
        wrapper.appendChild(a);
        wrapper.appendChild(lockBtn);

        lockBtn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            const state          = toggleUnlocked(type, src.name);
            e.target.textContent = state ? "🔓" : "🔒";
            e.target.title       = state ? "Remove from unlocked" : "Unlock to open with 'Open Unlocked'";
        };

        results.appendChild(wrapper);
    }

    // ── "Add tool" card at the end ──
    const addCard = document.createElement("div");
    addCard.className = "card-wrapper add-tool-wrapper";
    const addBtn = document.createElement("div");
    addBtn.className = "link-card add-tool-card";
    addBtn.title = "Add custom tool";
    addBtn.innerHTML = `<span class="add-tool-plus">+</span><span class="add-tool-label">Add tool</span>`;
    addBtn.onclick = () => openCustomToolModal(type);
    addCard.appendChild(addBtn);
    results.appendChild(addCard);

    // ── Drag-to-reorder: init SortableJS on the results container ──
    if (window.Sortable) {
        if (results._sortable) results._sortable.destroy();

        const isTouchDevice = window.matchMedia("(hover: none) and (pointer: coarse)").matches;

        results._sortable = new Sortable(results, {
            animation: 150,
            ghostClass:  "sortable-ghost",
            chosenClass: "sortable-chosen",
            dragClass:   "sortable-drag",
            filter:      ".add-tool-wrapper",
            preventOnFilter: false,
            handle:           isTouchDevice ? ".drag-handle" : undefined,
            delay:            isTouchDevice ? 0 : 0,
            delayOnTouchOnly: false,
            touchStartThreshold: 4,
            onEnd() {
                const names = [...results.querySelectorAll(".card-wrapper[data-name]")]
                    .map(el => el.dataset.name)
                    .filter(Boolean);
                saveOrder(type, names);
            }
        });
    }
}

/* ================= CUSTOM TOOLS ================= */
const CUSTOM_TOOLS_KEY = "soc_custom_tools";

function loadCustomTools() {
    try { return JSON.parse(localStorage.getItem(CUSTOM_TOOLS_KEY) || "{}"); } catch { return {}; }
}

function saveCustomTools(data) {
    try { localStorage.setItem(CUSTOM_TOOLS_KEY, JSON.stringify(data)); } catch {}
}

function getCustomToolsForType(type) {
    const all = loadCustomTools();
    return all[type] || [];
}

function addCustomTool(type, tool) {
    const all = loadCustomTools();
    if (!all[type]) all[type] = [];
    all[type].push(tool);
    saveCustomTools(all);
}

function deleteCustomTool(type, name) {
    const all = loadCustomTools();
    if (!all[type]) return;
    all[type] = all[type].filter(t => t.name !== name);
    saveCustomTools(all);
}

function openCustomToolModal(type) {
    // Capture current input value at the moment of opening
    const currentRaw = inputData.value.trim();

    // Remove existing modal if any
    document.getElementById("customToolModal")?.remove();

    const types = ["ipv4","ipv6","domain","url","hash","email","text"];

    const overlay = document.createElement("div");
    overlay.id        = "customToolModal";
    overlay.className = "modal-overlay";
    overlay.onclick   = e => { if (e.target === overlay) { overlay.remove(); document.removeEventListener("keydown", onKeyDown); } };

    const box = document.createElement("div");
    box.className = "modal-box";

    box.innerHTML = `
        <h3 class="modal-title">Add custom tool</h3>
        <label class="modal-label">Name
            <input id="ctName" class="modal-input" type="text" placeholder="My Tool" maxlength="40">
        </label>
        <label class="modal-label">URL <span class="modal-hint">use <code id="ctDataPlaceholder" title="Click to copy">{data}</code> as IoC placeholder</span>
            <input id="ctUrl" class="modal-input" style="margin-top:8px" type="text" placeholder="https://example.com/search?q={data}">
        </label>
        <label class="modal-label">IoC type
            <select id="ctType" class="modal-input">
                <option value="all">All types</option>
                ${types.map(t => `<option value="${t}" ${t === type ? "selected" : ""}>${t}</option>`).join("")}
            </select>
        </label>
        <div id="ctError" class="modal-error" style="display:none"></div>
        <div class="modal-actions">
            <button id="ctCancel" class="modal-btn modal-btn-cancel">Cancel</button>
            <button id="ctSave"   class="modal-btn modal-btn-save">Save</button>
        </div>
    `;

    overlay.appendChild(box);
    document.body.appendChild(overlay);

    // {data} click to copy
    const dataTag = document.getElementById("ctDataPlaceholder");
    dataTag.style.cursor = "pointer";
    dataTag.onclick = () => {
        navigator.clipboard.writeText("{data}");
        const orig = dataTag.textContent;
        dataTag.textContent = "Copied!";
        setTimeout(() => dataTag.textContent = orig, 1000);
    };

    const closeModal = () => { overlay.remove(); document.removeEventListener("keydown", onKeyDown); };

    document.getElementById("ctCancel").onclick = closeModal;
    document.getElementById("ctSave").onclick   = () => {
        const name    = document.getElementById("ctName").value.trim();
        const url     = document.getElementById("ctUrl").value.trim();
        const selType = document.getElementById("ctType").value;
        const errEl   = document.getElementById("ctError");

        // Validation
        if (!name) { showModalError(errEl, "Name is required."); return; }
        if (!url.includes("{data}")) { showModalError(errEl, "URL must contain {data}."); return; }
        if (!url.startsWith("https://") && !url.startsWith("http://")) { showModalError(errEl, "URL must start with http:// or https://"); return; }

        const existing = getCustomToolsForType(selType);
        if (selType !== "all" && existing.some(t => t.name.toLowerCase() === name.toLowerCase())) {
            showModalError(errEl, `A tool named "${name}" already exists for ${selType}.`); return;
        }

        const typesToSave = selType === "all" ? types : [selType];
        typesToSave.forEach(t => {
            const ex = getCustomToolsForType(t);
            if (!ex.some(e => e.name.toLowerCase() === name.toLowerCase())) {
                addCustomTool(t, { name, url });
            }
        });
        closeModal();
        renderLinks(currentRaw);
        showToast(`"${name}" added!`);
    };

    // Focus name input
    setTimeout(() => document.getElementById("ctName")?.focus(), 50);

    // Enter to save, Escape to close
    const onKeyDown = (e) => {
        if (e.key === "Escape") closeModal();
        if (e.key === "Enter" && document.activeElement?.id !== "ctCancel") {
            document.getElementById("ctSave")?.click();
        }
    };
    document.addEventListener("keydown", onKeyDown);
}

function showModalError(el, msg) {
    el.textContent  = msg;
    el.style.display = "block";
}

/* ================= SETTINGS MENU ================= */
const CUSTOM_RSS_KEY = "soctk_custom_rss";
const CONFIG_KEYS = [ORDER_KEY, OPEN_PREF_KEY, CUSTOM_TOOLS_KEY, "theme", CUSTOM_RSS_KEY];

document.getElementById("settingsToggle").onclick = (e) => {
    e.stopPropagation();
    const dd = document.getElementById("settingsDropdown");
    dd.style.display = dd.style.display === "none" ? "flex" : "none";
};

// Close dropdown when clicking outside
document.addEventListener("click", () => {
    document.getElementById("settingsDropdown").style.display = "none";
});

document.getElementById("settingsDropdown").onclick = e => e.stopPropagation();

// ── Export ──
document.getElementById("exportConfig").onclick = () => {
    const config = {};
    CONFIG_KEYS.forEach(k => {
        try { config[k] = JSON.parse(localStorage.getItem(k) || "null"); } catch {}
    });
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = "soctoolkit-config.json";
    a.click();
    URL.revokeObjectURL(url);
    document.getElementById("settingsDropdown").style.display = "none";
    showToast("Config exported!");
};

// ── Import ──
document.getElementById("importConfigInput").onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        try {
            const config = JSON.parse(ev.target.result);
            let applied  = 0;
            CONFIG_KEYS.forEach(k => {
                if (config[k] !== undefined && config[k] !== null) {
                    localStorage.setItem(k, JSON.stringify(config[k]));
                    applied++;
                }
            });
            if (applied === 0) { showToast("Nothing to import."); return; }
            document.getElementById("settingsDropdown").style.display = "none";
            showToast("Config imported! Reloading...");
            setTimeout(() => location.reload(), 1200);
        } catch {
            showToast("Invalid config file.");
        }
    };
    reader.readAsText(file);
    e.target.value = ""; // reset so same file can be re-imported
};

// ── Reset ──
document.getElementById("resetConfig").onclick = () => {
    if (!confirm("Restore defaults? This will remove your custom tools, order, unlock preferences and news cache.")) return;
    CONFIG_KEYS.forEach(k => localStorage.removeItem(k));
    // Clear all feed caches (soctk_feed_*)
    Object.keys(localStorage)
        .filter(k => k.startsWith(LS_FEED_PREFIX))
        .forEach(k => localStorage.removeItem(k));
    document.getElementById("settingsDropdown").style.display = "none";
    showToast("Restored! Reloading...");
    setTimeout(() => location.reload(), 1200);
};

/* ================= EVENTS ================= */
lookupBtn.onclick = () => renderLinks(inputData.value.trim());

// Enter = lookup, Shift+Enter = newline
inputData.addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        renderLinks(inputData.value.trim());
    }
});

// Auto-size textarea width to fit placeholder text — runs after full paint
window.addEventListener("load", () => {
    const placeholder = inputData.getAttribute("placeholder") || "";
    const canvas2     = document.createElement("canvas");
    const ctx2        = canvas2.getContext("2d");
    const style       = window.getComputedStyle(inputData);
    ctx2.font         = `${style.fontSize} ${style.fontFamily}`;
    const textWidth   = ctx2.measureText(placeholder).width;
    const padding     = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 20;
    const width       = Math.ceil(textWidth + padding);
    inputData.style.width = Math.min(width, window.innerWidth * 0.9) + "px";
});

// FIX: "Open Unlocked" — opens only sources the user has unlocked (🔓)
// Supports multiple IoCs: opens all IoCs per unlocked source
openUnlocked.onclick = async () => {
    const raw = inputData.value.trim();
    if (!raw) return;

    const iocs  = parseMultipleIoCs(raw);
    if (!iocs.length) return;

    const t     = detectType(iocs[0]);
    const prefs = loadOpenPrefs();

    let opened = 0;
    for (const src of getOrderedSources(t)) {
        if (prefs[`${t}|${src.name}`] !== true) continue;

        for (const ioc of iocs) {
            const p       = await prepareData(ioc, t, src);
            const rawLink = src.url.replace("{data}", p);
            const lower   = rawLink.toLowerCase();
            if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
                console.warn("Blocked non-http URL for", src.name);
                continue;
            }
            window.open(rawLink, "_blank");
            opened++;
        }
    }

    if (opened === 0) {
        showToast(`No unlocked tools. Click 🔒 on any card to unlock it.`);
    }
};

/* ================= TOAST NOTIFICATION ================= */
function showToast(message, duration = 3500) {

    // Create container (stack de toasts)
    let container = document.getElementById("soc-toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "soc-toast-container";
        container.style.cssText = `
            position: fixed;
            top: 25px;
            right: 60px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            z-index: 9999;
        `;
        document.body.appendChild(container);
    }

    // Create individual toast
    const toast = document.createElement("div");
    toast.style.cssText = `
        background: #222;
        color: #fff;
        border: 1px solid #000;
        padding: 12px 20px;
        border-radius: 8px;
        font-family: "Courier New", monospace;
        font-size: 13px;
        max-width: 320px;
        opacity: 0;
        transform: translateX(20px);
        transition: all 0.3s ease;
        box-shadow: 0 6px 18px rgba(0,0,0,0.4);
        cursor: default;
    `;

    toast.textContent = message;
    container.appendChild(toast);

    // Reflow
    requestAnimationFrame(() => {
        toast.style.opacity = "1";
        toast.style.transform = "translateX(0)";
    });

    // Auto remove
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(20px)";
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, duration);
}

/* ================= BOOT SEQUENCE ================= */
const bootLines = [
    "[ OK ] Starting server..",
    "[ OK ] Loading modules..",
    "[ OK ] Establishing secure environment",
    "[ OK ] Coded by Jimmy Bianco",
    "[ OK ] Redirecting to soctoolkit.com"
];

let line = 0;
const bootEl    = document.getElementById("bootOutput");
const appEl     = document.getElementById("app");
const queryInput = document.getElementById("inputData");

function bootSequence() {
    if (line < bootLines.length) {
        bootEl.textContent += bootLines[line] + "\n";
        line++;
        setTimeout(bootSequence, 350);
    } else {
        setTimeout(() => {
            document.getElementById("bootScreen").style.display = "none";
            appEl.style.display = "block";
            queryInput.focus();
            loadNews();
        }, 500);
    }
}

// FIX: use addEventListener instead of window.onload to avoid overwriting other handlers
window.addEventListener("load", bootSequence);

/* ================= THEME TOGGLE ================= */
const themeBtn = document.getElementById("themeToggle");

function applyTheme(theme) {
    document.body.classList.remove("hacker", "modern");
    document.body.classList.add(theme);
    themeBtn.textContent = (theme === "modern" ? "🌙" : "🔆") + " Toggle theme";
    localStorage.setItem("theme", theme);
}

// FIX: use addEventListener to coexist with bootSequence listener
window.addEventListener("load", () => {
    const savedTheme = localStorage.getItem("theme") || "hacker";
    applyTheme(savedTheme);
});

themeBtn.addEventListener("click", () => {
    const current = document.body.classList.contains("modern") ? "modern" : "hacker";
    applyTheme(current === "hacker" ? "modern" : "hacker");
    // Keep dropdown open so user can see other options
});

/* ================= UTC CLOCK ================= */
const utcClock = document.getElementById("utcClock");

function updateUTCClock() {
    utcClock.textContent = new Date().toISOString().replace("T", " ").replace("Z", " UTC");
}

setInterval(updateUTCClock, 1000);
updateUTCClock();

/* ================= FOOTER CURRENT YEAR ================= */
document.getElementById("currentYear").textContent = new Date().getFullYear();

/* ================= FOOTER TOGGLE ================= */
document.querySelectorAll(".footer-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        const targetId = btn.dataset.target;
        const section  = document.getElementById(targetId);
        const panel    = document.getElementById("footerPanel");
        const ticker   = document.getElementById("newsTicker");
        const opening  = section.style.display !== "block";

        document.querySelectorAll(".footer-section").forEach(s => s.style.display = "none");
        document.querySelectorAll(".footer-btn").forEach(b => b.classList.remove("active"));

        if (opening) {
            section.style.display = "block";
            btn.classList.add("active");
        }

        // Measure actual content height before CSS transition kicks in
        const panelH         = opening ? panel.scrollHeight : 0;
        _footerPanelOpen     = opening;
        _footerPanelH        = panelH;
        panel.classList.toggle("open", opening);

        ticker.style.bottom  = (FOOTER_BAR_H + panelH) + "px";
        document.body.style.paddingBottom = _tickerPaddingBottom();
    });
});
/* ================= PARTICLES SYSTEM ================= */

const canvas = document.getElementById("particlesCanvas");
const ctx = canvas.getContext("2d");

let particles = [];
let mouse = { x: null, y: null };

// ── Cursor trail ──
const TRAIL_LENGTH = 24;
const TRAIL_TTL    = 120; // ms before a point expires
const trail = [];

// ── Theme helper ──
function isModern() { return document.body.classList.contains("modern"); }

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}
resizeCanvas();
window.addEventListener("resize", resizeCanvas);

window.addEventListener("mousemove", e => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    trail.push({ x: e.clientX, y: e.clientY, t: Date.now() });
    if (trail.length > TRAIL_LENGTH) trail.shift();
});

// ── Click: spawn regular particles at click position ──
const MAX_PARTICLES = 200;
window.addEventListener("click", e => {
    const tag = e.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "BUTTON" || tag === "A" || e.target.closest("a, button, .ioc-copy, .ioc-header-copy, .link-card, #footerStack")) return;
    for (let i = 0; i < 8; i++) {
        if (particles.length >= MAX_PARTICLES) particles.shift(); // remove oldest
        const p = new Particle();
        p.x = e.clientX;
        p.y = e.clientY;
        particles.push(p);
    }
});

class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.size = Math.random() * 2 + 1;
        this.speedX = (Math.random() - 0.5) * 0.7;
        this.speedY = (Math.random() - 0.5) * 0.7;
    }

    update() {
        this.x += this.speedX;
        this.y += this.speedY;

        // rebote suave
        if (this.x < 0 || this.x > canvas.width) this.speedX *= -1;
        if (this.y < 0 || this.y > canvas.height) this.speedY *= -1;

        // reacción al mouse
        if (mouse.x === null || mouse.y === null) return;
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 120) {
            this.x -= dx * 0.02;
            this.y -= dy * 0.02;
        }
    }

    draw() {
        ctx.fillStyle = isModern() ? "rgba(60,60,80,0.4)" : "rgba(0,255,0,0.7)";
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
    }
}

// ── Draw cursor trail ──
function drawTrail() {
    // Remove points older than TTL
    const now = Date.now();
    while (trail.length && now - trail[0].t > TRAIL_TTL) trail.shift();

    if (trail.length < 2) return;
    const modern = isModern();

    for (let i = 1; i < trail.length; i++) {
        const alpha  = i / trail.length;
        const width  = (i / trail.length) * 2.5;
        ctx.beginPath();
        ctx.moveTo(trail[i - 1].x, trail[i - 1].y);
        ctx.lineTo(trail[i].x, trail[i].y);
        ctx.strokeStyle = modern
            ? `rgba(99,102,241,${alpha * 0.5})`
            : `rgba(0,255,0,${alpha * 0.6})`;
        ctx.lineWidth = width;
        ctx.lineCap   = "round";
        ctx.stroke();
    }
}

function initParticles() {
    particles = [];
    const count = window.innerWidth < 768 ? 60 : 120;

    for (let i = 0; i < count; i++) {
        particles.push(new Particle());
    }
}

function connectParticles() {
    const modern = isModern();
    const lineColor = modern ? "rgba(100,100,120,0.08)" : "rgba(0,255,0,0.1)";
    for (let a = 0; a < particles.length; a++) {
        for (let b = a; b < particles.length; b++) {
            const dx = particles[a].x - particles[b].x;
            const dy = particles[a].y - particles[b].y;
            const distance = dx * dx + dy * dy;

            if (distance < 10000) {
                ctx.strokeStyle = lineColor;
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(particles[a].x, particles[a].y);
                ctx.lineTo(particles[b].x, particles[b].y);
                ctx.stroke();
            }
        }
    }
}

function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw trail first (below particles)
    drawTrail();

    // Update and draw all particles
    particles.forEach(p => {
        p.update();
        p.draw();
    });

    connectParticles();

    requestAnimationFrame(animateParticles);
}

window.addEventListener("load", () => {
    initParticles();
    animateParticles();
});
/* ================= NEWS FEED ================= */
const NEWS_SOURCES = [
    { name: "The Hacker News",  rss: "https://feeds.feedburner.com/TheHackersNews" },
    { name: "BleepingComputer", rss: "https://www.bleepingcomputer.com/feed/" },
    { name: "HudsonRock",       rss: "https://www.infostealers.com/feed/" },
    { name: "Unit 42",          rss: "https://unit42.paloaltonetworks.com/feed/" },
    { name: "Microsoft",        rss: "https://www.microsoft.com/en-us/security/blog/feed/" },
    { name: "CrowdStrike",      rss: "https://www.crowdstrike.com/blog/feed/" },
    { name: "Securelist",       rss: "https://securelist.com/feed/" },
    { name: "The DFIR Report",  rss: "https://thedfirreport.com/feed/" },
];

const RSS2JSON       = "https://api.rss2json.com/v1/api.json?rss_url=";
const NEWS_TTL_MS    = 5 * 60 * 60 * 1000; // 5 hours
const LS_FEED_PREFIX = "soctk_feed_";
let _newsResults    = null;
let _newsFilter     = "All";
let _newsPanelOpen  = false;
let _lastTickerItems = [];
const TICKER_MODE_KEY = "tickerMode";
let _tickerMode     = localStorage.getItem(TICKER_MODE_KEY) || "card";

let _customSources = [];
(function loadCustomSources() {
    try { _customSources = JSON.parse(localStorage.getItem(CUSTOM_RSS_KEY) || "[]"); }
    catch { _customSources = []; }
})();

function saveCustomSources() {
    try { localStorage.setItem(CUSTOM_RSS_KEY, JSON.stringify(_customSources)); } catch {}
}

function getActiveSources() {
    return [...NEWS_SOURCES, ..._customSources];
}

function _lsKey(name) {
    return LS_FEED_PREFIX + name.replace(/\s+/g, "_");
}

function getStoredFeed(name) {
    try {
        const raw = localStorage.getItem(_lsKey(name));
        return raw ? JSON.parse(raw) : null; // { ts, items } or null
    } catch { return null; }
}

function storeAndMergeFeed(name, incoming) {
    const existing = (getStoredFeed(name) || {}).items || [];
    const seen     = new Set();
    const merged   = [...incoming, ...existing].filter(item => {
        const key = item.link || item.guid || item.title;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
    merged.sort((a, b) => parseNewsDate(b.pubDate) - parseNewsDate(a.pubDate));
    const final = merged.slice(0, ITEMS_PER_SOURCE);
    try { localStorage.setItem(_lsKey(name), JSON.stringify({ ts: Date.now(), items: final })); } catch {}
    return final;
}

async function fetchFeed(source, forceRefresh = false) {
    const stored  = getStoredFeed(source.name);
    const isFresh = stored && (Date.now() - stored.ts < NEWS_TTL_MS);

    if (isFresh && !forceRefresh) {
        return { source, items: stored.items, ok: true };
    }

    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 8000);
    try {
        const res  = await fetch(RSS2JSON + encodeURIComponent(source.rss), { signal: controller.signal });
        const data = await res.json();
        clearTimeout(tid);
        if (data.status !== "ok") throw new Error("bad status");
        const merged = storeAndMergeFeed(source.name, data.items || []);
        return { source, items: merged, ok: true };
    } catch {
        clearTimeout(tid);
        // Fallback to stale cache rather than showing nothing
        if (stored && stored.items.length) {
            return { source, items: stored.items, ok: true };
        }
        return { source, items: [], ok: false };
    }
}

const TZ_MAP = {
    CEST:"+0200", CET:"+0100", BST:"+0100", IST:"+0530",
    EDT:"-0400",  EST:"-0500", CDT:"-0500", CST:"-0600",
    MDT:"-0600",  MST:"-0700", PDT:"-0700", PST:"-0800",
};

function parseNewsDate(str) {
    if (!str) return NaN;
    // Replace non-standard timezone abbreviations (e.g. CEST → +0200)
    let s = str.trim().replace(/\b([A-Z]{2,5})\b$/, m => TZ_MAP[m] || m);
    // rss2json format: "2024-06-28 10:30:00" — normalize to ISO
    if (/^\d{4}-\d{2}-\d{2} /.test(s)) {
        s = s.replace(" ", "T");
        if (!/[Z+\-]\d+$/.test(s)) s += "Z";
    }
    const t = new Date(s).getTime();
    return isNaN(t) ? new Date(str).getTime() : t;
}

function timeAgo(dateStr) {
    const diff = Date.now() - parseNewsDate(dateStr);
    const h = Math.floor(diff / 3600000);
    const d = Math.floor(diff / 86400000);
    if (h < 1)  return "just now";
    if (h < 24) return `${h}h ago`;
    return `${d}d ago`;
}

const ITEMS_PER_SOURCE = 15;

function getThumb(item) {
    if (item.thumbnail && item.thumbnail.startsWith("http")) return item.thumbnail;
    if (item.enclosure?.link && /^https?:\/\//.test(item.enclosure.link)) return item.enclosure.link;
    // Extract first <img src> from content or description HTML
    const html = item.content || item.description || "";
    const m    = html.match(/<img[^>]+src=["']([^"']+)["']/i);
    if (m && /^https?:\/\//.test(m[1])) return m[1];
    return null;
}

function stripHtml(html) {
    return (html || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function renderNewsUI() {
    if (!_newsResults) return;

    const filtersEl = document.getElementById("newsFilters");
    const feedEl    = document.getElementById("newsFeed");

    // ── Filter buttons ──
    filtersEl.innerHTML = "";
    ["All", ..._newsResults.map(r => r.source.name)].forEach(name => {
        const failed   = name !== "All" && _newsResults.find(r => r.source.name === name && !r.ok);
        const isCustom = name !== "All" && _customSources.some(s => s.name === name);
        const btn      = document.createElement("button");
        btn.className  = "news-filter-btn" + (_newsFilter === name ? " news-filter-active" : "");
        btn.onclick    = () => { _newsFilter = name; renderNewsUI(); };

        const label = document.createElement("span");
        label.textContent = name + (failed ? " ⚠" : "");
        btn.appendChild(label);

        if (isCustom) {
            btn.classList.add("has-remove");
            const x = document.createElement("span");
            x.className   = "news-filter-remove";
            x.textContent = "❌";
            x.title       = "Remove this feed";
            x.onclick     = e => { e.stopPropagation(); removeCustomSource(name); };
            btn.appendChild(x);
        }

        filtersEl.appendChild(btn);
    });

    const addRssBtn     = document.createElement("button");
    addRssBtn.className = "news-filter-btn news-add-rss-btn";
    addRssBtn.title     = "Add custom RSS feed";
    addRssBtn.innerHTML = `<span class="add-rss-plus">+</span><span class="add-rss-label">RSS</span>`;
    addRssBtn.onclick   = openAddRssModal;
    filtersEl.appendChild(addRssBtn);

    // ── Collect + filter items ──
    let items = [];
    _newsResults.forEach(({ source, items: src, ok }) => {
        if (!ok) return;
        src.slice(0, ITEMS_PER_SOURCE).forEach(item => items.push({ ...item, _source: source.name }));
    });

    if (_newsFilter !== "All") items = items.filter(i => i._source === _newsFilter);
    items.sort((a, b) => parseNewsDate(b.pubDate) - parseNewsDate(a.pubDate));

    // ── Render items ──
    feedEl.innerHTML = "";

    if (!items.length) {
        const p       = document.createElement("p");
        p.className   = "news-status";
        p.textContent = "No articles found.";
        feedEl.appendChild(p);
        return;
    }

    items.forEach(item => {
        const a   = document.createElement("a");
        a.className = "news-card";
        a.href      = item.link;
        a.target    = "_blank";
        a.rel       = "noopener noreferrer";

        const thumb = getThumb(item);
        if (thumb) {
            const img     = document.createElement("img");
            img.className = "news-thumb";
            img.src       = thumb;
            img.alt       = "";
            img.onerror   = () => img.remove();
            img.onload    = () => { if (img.naturalWidth < 50 || img.naturalHeight < 50) img.remove(); };
            a.appendChild(img);
        }

        const body       = document.createElement("div");
        body.className   = "news-body";

        const metaRow    = document.createElement("div");
        metaRow.className = "news-meta-row";

        const badge       = document.createElement("span");
        badge.className   = "news-source-badge";
        badge.textContent = item._source;

        const age         = document.createElement("span");
        age.className     = "news-item-age";
        age.textContent   = timeAgo(item.pubDate);

        metaRow.appendChild(badge);
        metaRow.appendChild(age);

        const title       = document.createElement("span");
        title.className   = "news-item-title";
        title.textContent = item.title;

        body.appendChild(metaRow);
        body.appendChild(title);

        const rawDesc = stripHtml(item.description || "");
        if (rawDesc) {
            const desc       = document.createElement("span");
            desc.className   = "news-item-desc";
            desc.textContent = rawDesc;
            body.appendChild(desc);
        }

        a.appendChild(body);
        feedEl.appendChild(a);
    });
}

function removeCustomSource(name) {
    _customSources = _customSources.filter(s => s.name !== name);
    saveCustomSources();
    try { localStorage.removeItem(_lsKey(name)); } catch {}
    if (_newsFilter === name) _newsFilter = "All";
    loadNews();
}

function openAddRssModal() {
    document.getElementById("addRssModal")?.remove();

    const overlay = document.createElement("div");
    overlay.id        = "addRssModal";
    overlay.className = "modal-overlay";
    overlay.onclick   = e => { if (e.target === overlay) overlay.remove(); };

    const box = document.createElement("div");
    box.className = "modal-box";
    box.innerHTML = `
        <h3 class="modal-title">Add RSS Feed</h3>
        <label class="modal-label">Name
            <input id="rssName" class="modal-input" type="text" placeholder="e.g. My Blog" maxlength="40">
        </label>
        <label class="modal-label">RSS URL
            <input id="rssUrl" class="modal-input" type="url" placeholder="https://example.com/feed.xml">
        </label>
        <div class="modal-actions">
            <button class="modal-btn modal-btn-primary" id="rssConfirm">Add Feed</button>
            <button class="modal-btn" id="rssCancel">Cancel</button>
        </div>`;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    document.getElementById("rssName").focus();

    const confirmRss = () => {
        const name = document.getElementById("rssName").value.trim();
        const rss  = document.getElementById("rssUrl").value.trim();

        if (!name) { showToast("Enter a name for the feed."); return; }
        if (!rss || !/^https?:\/\//i.test(rss)) { showToast("Enter a valid RSS URL."); return; }
        if (getActiveSources().some(s => s.name === name)) {
            showToast("A source with that name already exists."); return;
        }

        _customSources.push({ name, rss });
        saveCustomSources();
        overlay.remove();
        showToast(`Added "${name}" — loading…`);
        loadNews();
    };

    document.getElementById("rssCancel").onclick  = () => overlay.remove();
    document.getElementById("rssConfirm").onclick = confirmRss;
    box.addEventListener("keydown", e => {
        if (e.key === "Enter" && document.activeElement?.id !== "rssCancel") confirmRss();
        if (e.key === "Escape") overlay.remove();
    });
}

function updateTicker(items) {
    const ticker  = document.getElementById("newsTicker");
    const content = document.getElementById("tickerContent");

    // only show items that have an image
    const withImg = items.filter(item => getThumb(item));
    if (!withImg.length) { ticker.style.display = "none"; return; }

    content.innerHTML = "";

    const makeSet = () => {
        const frag = document.createDocumentFragment();
        withImg.forEach(item => {
            const a = document.createElement("a");
            a.className = "ticker-item";
            a.href      = item.link;
            a.target    = "_blank";
            a.rel       = "noopener noreferrer";
            a.addEventListener("click", e => e.stopPropagation());

            const img     = document.createElement("img");
            img.className = "ticker-thumb";
            img.src       = getThumb(item);
            img.alt       = "";
            img.onerror   = () => { a.style.display = "none"; };
            img.onload    = () => { if (img.naturalWidth < 50 || img.naturalHeight < 50) a.style.display = "none"; };
            a.appendChild(img);

            const body = document.createElement("div");
            body.className = "ticker-card-body";

            const source       = document.createElement("span");
            source.className   = "ticker-card-source";
            source.textContent = item._source || "";
            body.appendChild(source);

            const title       = document.createElement("span");
            title.className   = "ticker-card-title";
            title.textContent = item.title;
            body.appendChild(title);

            a.appendChild(body);
            frag.appendChild(a);
        });
        return frag;
    };

    content.appendChild(makeSet());
    content.appendChild(makeSet()); // duplicate for seamless loop

    _lastTickerItems = withImg;
    _applyTickerSpeed();

    ticker.dataset.mode = _newsPanelOpen ? "compact" : _tickerMode;
    ticker.style.display = "flex";
}

function _applyTickerSpeed() {
    const content = document.getElementById("tickerContent");
    if (!content || !_lastTickerItems.length) return;
    const effectiveMode = _newsPanelOpen ? "compact" : _tickerMode;
    let duration;
    if (effectiveMode === "compact") {
        const totalChars = _lastTickerItems.reduce((s, i) => s + i.title.length, 0);
        duration = Math.max(80, totalChars * 0.22); // slower in compact
    } else {
        duration = Math.max(40, _lastTickerItems.length * 220 / 80); // card: px-based
    }
    content.style.animationDuration = `${duration}s`;
}

const FOOTER_BAR_H  = 36;
let _savedTickerMode = null;
let _footerPanelOpen = false;
let _footerPanelH    = 0;

function _tickerPaddingBottom() {
    return `${(_tickerMode === "card" ? 160 : 62) + FOOTER_BAR_H + _footerPanelH}px`;
}

function _applyModeBtn() {
    const btn = document.getElementById("tickerModeToggle");
    btn.textContent = _tickerMode === "card" ? "≡" : "⊞";
    btn.title       = _tickerMode === "card" ? "Switch to compact view" : "Switch to card view";
}

function toggleTickerMode() {
    _tickerMode = _tickerMode === "card" ? "compact" : "card";
    localStorage.setItem(TICKER_MODE_KEY, _tickerMode);
    _applyModeBtn();
    document.getElementById("newsTicker").dataset.mode = _tickerMode;
    document.body.style.paddingBottom = _tickerPaddingBottom();
    _applyTickerSpeed();
}

async function loadNews(forceRefresh = false) {
    const active = getActiveSources();
    document.getElementById("newsFeed").innerHTML    = `<p class="news-status">Loading news from ${active.length} sources…</p>`;
    document.getElementById("newsFilters").innerHTML = "";

    const settled = await Promise.allSettled(active.map(s => fetchFeed(s, forceRefresh)));
    _newsResults  = active.map((source, i) => {
        const r = settled[i];
        return r.status === "fulfilled" ? r.value : { source, items: [], ok: false };
    });

    // Collect all items across sources for the ticker
    const allItems = [];
    _newsResults.forEach(({ source, items, ok }) => {
        if (!ok) return;
        items.slice(0, ITEMS_PER_SOURCE).forEach(item => allItems.push({ ...item, _source: source.name }));
    });
    allItems.sort((a, b) => parseNewsDate(b.pubDate) - parseNewsDate(a.pubDate));
    updateTicker(allItems);

    renderNewsUI();
}

function toggleNewsSection() {
    const section = document.getElementById("newsSection");
    const ticker  = document.getElementById("newsTicker");
    const badge   = document.querySelector(".ticker-expand-badge");
    _newsPanelOpen = section.style.display === "none";
    section.style.display = _newsPanelOpen ? "block" : "none";

    if (_newsPanelOpen) {
        // Save current mode and force compact
        _savedTickerMode = _tickerMode;
        _tickerMode = "compact";
        _applyModeBtn();
        ticker.dataset.mode = "compact";
        document.body.style.paddingBottom = _tickerPaddingBottom();
        if (badge) badge.textContent = "▼ CLOSE";
        _applyTickerSpeed();
        if (!_newsResults) loadNews();
        requestAnimationFrame(() => section.scrollIntoView({ behavior: "smooth", block: "start" }));
    } else {
        // Restore saved mode
        if (_savedTickerMode !== null) {
            _tickerMode = _savedTickerMode;
            _savedTickerMode = null;
            localStorage.setItem(TICKER_MODE_KEY, _tickerMode);
        }
        _applyModeBtn();
        ticker.dataset.mode = _tickerMode;
        document.body.style.paddingBottom = _tickerPaddingBottom();
        if (badge) badge.textContent = "▲ ALL";
        _applyTickerSpeed();
    }
}

document.getElementById("tickerLabel").addEventListener("click", toggleNewsSection);
document.querySelector(".ticker-expand-badge")?.addEventListener("click", toggleNewsSection);
document.getElementById("tickerModeToggle").addEventListener("click", e => {
    e.stopPropagation();
    toggleTickerMode();
});
document.getElementById("newsRefresh").addEventListener("click", () => loadNews(true));

/* ================= END ================= */
