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
async function prepareData(input, type, src) {
    let data = input;

    if (type === "url" && src.needsHash) {
        data = await sha256(input);
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
    return JSON.parse(localStorage.getItem(OPEN_PREF_KEY) || "{}");
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

// Returns sources[type] reordered to match saved order (new sources appended at end)
function getOrderedSources(type) {
    const list    = sources[type];
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

        // Mobile drag handle — only visible on touch devices
        const dragHandle = document.createElement("span");
        dragHandle.className   = "drag-handle";
        dragHandle.textContent = "⠿";
        dragHandle.title       = "Drag to reorder";

        titleDiv.appendChild(img);
        titleDiv.appendChild(nameSpan);
        titleDiv.appendChild(lockBtn);
        titleDiv.appendChild(dragHandle);

        const urlSpan = document.createElement("span");
        urlSpan.className   = "url";
        urlSpan.textContent = iocs.length > 1 ? `${iocs.length} IoCs → ${src.name}` : firstLink;

        a.appendChild(titleDiv);
        a.appendChild(urlSpan);

        lockBtn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            const state          = toggleUnlocked(type, src.name);
            e.target.textContent = state ? "🔓" : "🔒";
            e.target.title       = state ? "Remove from unlocked" : "Unlock to open with 'Open Unlocked'";
        };

        results.appendChild(a);
    }

    // ── Drag-to-reorder: init SortableJS on the results container ──
    if (window.Sortable) {
        if (results._sortable) results._sortable.destroy();

        const isTouchDevice = window.matchMedia("(hover: none) and (pointer: coarse)").matches;

        results._sortable = new Sortable(results, {
            animation: 150,
            ghostClass:  "sortable-ghost",
            chosenClass: "sortable-chosen",
            dragClass:   "sortable-drag",
            handle:           isTouchDevice ? ".drag-handle" : undefined,
            delay:            isTouchDevice ? 0 : 0,
            delayOnTouchOnly: false,
            touchStartThreshold: 4,
            onEnd() {
                const names = [...results.querySelectorAll(".link-card")]
                    .map(el => el.querySelector(".title span:not(.lock-btn):not(.drag-handle):not(.ioc-count-badge)")?.textContent?.trim())
                    .filter(Boolean);
                saveOrder(type, names);
            }
        });
    }
}

/* ================= EVENTS ================= */
lookupBtn.onclick = () => renderLinks(inputData.value.trim());

// Enter = lookup, Shift+Enter = newline
inputData.addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        renderLinks(inputData.value.trim());
    }
});

// Auto-size textarea width to fit placeholder text
(function sizeInputToPlaceholder() {
    const placeholder = inputData.getAttribute("placeholder") || "";
    const canvas      = document.createElement("canvas");
    const ctx         = canvas.getContext("2d");
    const style       = window.getComputedStyle(inputData);
    ctx.font          = `${style.fontSize} ${style.fontFamily}`;
    const textWidth   = ctx.measureText(placeholder).width;
    const padding     = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 20; // +20 safety margin
    const width       = Math.ceil(textWidth + padding);
    inputData.style.width = Math.min(width, window.innerWidth * 0.9) + "px";
})();

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

    themeBtn.classList.remove("animate");
    void themeBtn.offsetWidth;
    themeBtn.classList.add("animate");

    themeBtn.textContent = theme === "modern" ? "🌙" : "🔆";
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

        document.querySelectorAll(".footer-section").forEach(sec => {
            if (sec !== section) sec.style.display = "none";
        });

        section.style.display = section.style.display === "block" ? "none" : "block";
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
window.addEventListener("click", e => {
    const tag = e.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "BUTTON" || tag === "A" || e.target.closest("a, button, .ioc-copy, .ioc-header-copy, .link-card, footer")) return;
    for (let i = 0; i < 8; i++) {
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
    for (let a = 0; a < particles.length; a++) {
        for (let b = a; b < particles.length; b++) {
            const dx = particles[a].x - particles[b].x;
            const dy = particles[a].y - particles[b].y;
            const distance = dx * dx + dy * dy;

            if (distance < 10000) {
                ctx.strokeStyle = isModern() ? "rgba(100,100,120,0.08)" : "rgba(0,255,0,0.1)";
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
/* ================= END ================= */
