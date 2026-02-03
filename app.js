/* ============== SOURCES ============== */
const sources = {
    ipv4: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}"},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"},
        {name:"WhatIsMyIPAddress", url:"https://whatismyipaddress.com/ip/{data}"},
        {name:"SPUR (detect VPNs)", url:"https://spur.us/context/{data}"},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
    ],
    ipv6: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}"},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"},
        {name:"WhatIsMyIPAddress", url:"https://whatismyipaddress.com/ip/{data}"},
        {name:"SPUR (detect VPNs)", url:"https://spur.us/context/{data}"},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
    ],
    url: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/url/{data}", needsHash:true, encode:true},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/url/{data}",encode:false},
        {name:"URLScan", url:"https://urlscan.io/search/#page.domain:{data}", encode:false, usesDomain:true, noWWW:true},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", usesDomain:true, noWWW:true},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}",encode:false},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}", usesDomain:true},
        {name:"Netcraft", url:"https://sitereport.netcraft.com/?url={data}"},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}"},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}", usesDomain:true},
        {name:"Hudson Rock Infostealer", url:"https://www.hudsonrock.com/search/domain/{data}", usesDomain:true, noWWW:true},
        {name:"Hudson Rock (URL Discovery)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={data}", usesDomain:true, noWWW:true},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:true, noWWW:true},
        {name:"Wayback Machine", url:"https://web.archive.org/web/{data}"},
        {name:"Wayback Machine (Save)", url:"https://web.archive.org/save/{data}"},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}", usesDomain:true},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
    ],
    domain: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/domain/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/domain/{data}"},
        {name:"URLScan", url:"https://urlscan.io/search/#page.domain:{data}", encode:false, usesDomain:true, noWWW:true},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", noWWW:true},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}"},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}"},
        {name:"Netcraft", url:"https://sitereport.netcraft.com/?url={data}"},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}"},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}"},
        {name:"HudsonRock Infostealer", url:"https://www.hudsonrock.com/search/domain/{data}", usesDomain:true, noWWW:true},
        {name:"HudsonRock (URL Discovery)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={data}", usesDomain:true, noWWW:true},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:true, noWWW:true},
        {name:"Wayback Machine", url:"https://web.archive.org/web/{data}"},
        {name:"Wayback Machine (Save)", url:"https://web.archive.org/save/{data}"},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
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
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
    ],
    email: [ 
        {name:"Have I Been Pwned", url:"https://haveibeenpwned.com/unifiedsearch/{data}", usesDomain:false, encode:false},
        {name:"HudsonRock Infostealer", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={data}", usesDomain:false, encode:false},
        {name:"SOCRadar (DarkWebReport)", url:"https://socradar.io/labs/app/dark-web-report?domain={data}", usesDomain:false},
        {name:"Intelbase", url:"https://intelbase.is/"},
        {name:"IntelX", url:"https://intelx.io/?s={data}&b=leaks.public.wikileaks,leaks.public.general,dumpster,documents.public.scihub", encode:false},
        {name:"Internxt DarkWeb Monitor", url:"https://internxt.com/dark-web-monitor", encode:false},
        {name:"Blacklist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
    ],
    text: [
        {name:"Google", url:"https://www.google.com/search?q={data}"},
        {name:"Translate", url:"https://translate.google.com/?sl=auto&tl=en&text={data}&op=translate"},
        {name:"LOLBAS", url:"https://lolbas-project.github.io/#{data}", encode:false},
        {name:"GTFOBins", url:"https://gtfobins.github.io/#{data}", encode:false},
        {name:"Mitre", url:"https://www.google.com/search?q=inurl:attack.mitre.org+{data}"},
        {name:"NIST NVD", url:"https://nvd.nist.gov/vuln/search#/nvd/home?keyword={data}&resultType=records"},
        {name:"CVE ORG", url:"https://www.cve.org/CVERecord?id={data}"},
        {name:"CVE RADAR", url:"https://socradar.io/labs/app/cve-radar/{data}"},
        {name:"Exploit DB", url:"https://www.exploit-db.com/search?q={data}"},
        {name:"Windows EventID", url:"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={data}"},
        {name:"Microsoft ErrorCode", url:"https://login.microsoftonline.com/error", encode:false},
        {name:"HudsonRock Infostealer (Username)", url:"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={data}", usesDomain:false},
        {name:"ClickFix Hunter", url:"https://clickfix.carsonww.com/domains?query={data}"},
        {name:"WikiLeaks", url:"https://search.wikileaks.org/?query={data}", encode:false},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input={data}", encode:false, base64:true},
        {name:"ExplainShell", url:"https://explainshell.com/explain?cmd={data}", encode:false, base64:false},
        {name:"Port Info", url:"https://speedguide.net/port.php?port={data}", encode:false, base64:false},
        {name:"MXToolBox - EmailHeaders", url:"https://mxtoolbox.com/EmailHeaders.aspx", encode:false},
        {name:"No More Ransom", url:"https://www.nomoreransom.org/crypto-sheriff.php"},
    ]
};

/* ================= DEFANG ================= */
function normalizeDefang(v){
    return v
        .replace(/^hxxps?:\/\//i,m=>m.toLowerCase().replace("hxxp","http"))
        .replace(/\[\.\]|\(\.\)|\{\.\}/g,".")
        .trim();
}
function defangValue(v){
    return v
        .replace(/^https?:\/\//i,m=>m.toLowerCase().replace("http","hxxp"))
        .replace(/\./g,"[.]");
}

function copyToClipboard(text){
    navigator.clipboard.writeText(text);
}

/* ============== DETECTORS ============== */
function isIPv4(i){ return /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(i); }
function isIPv6(i){ return /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(i); }
function isURL(i){ return /^https?:\/\/[^\s]+$/.test(i); }
function isDomain(i){ return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(i); }
function isHash(i){ return /^[a-fA-F0-9]{32,128}$/.test(i); }
function isEmail(i){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(i); }

function detectType(input){
    if(isIPv4(input)) return "ipv4";
    if(isIPv6(input)) return "ipv6";
    if(isURL(input)) return "url";
    if(isEmail(input)) return "email";
    if(isDomain(input)) return "domain";
    if(isHash(input)) return "hash";
    return "text";
}

/* ================= UTILITIES ================= */
function emailDomain(email){ return email.split("@")[1].toLowerCase(); }
function urlDomain(url){
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

async function sha256(input){
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

function toBase64(str) {
    return btoa(unescape(encodeURIComponent(str)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

/* ================= NORMALIZATION ================= */
async function prepareData(input, type, src) {
    let data = input;

    // Calculate hash if URL and the source requires it
    if (type === "url" && src.needsHash) {
        data = await sha256(input);
    }

    // If the source uses domain, extract it
    if (src.usesDomain) {
        if (type === "email") {
            data = emailDomain(input);
        } else if (type === "url" || type === "domain") {
            data = urlDomain(input);
        }
    }

    // Remove www. if noWWW is true
    if (src.noWWW) {
        data = data.replace(/^www\./i, "");
    }

    // Base64 has priority over URI encoding
    if (src.base64 === true) {
        data = toBase64(data);
        return data;
    }
    // Otherwise encodeURIComponent unless explicitly disabled
    else if (src.encode !== false) {
        data = encodeURIComponent(data);
    }

    return data;
}


/* ================= OPEN ALL PREFERENCES ================= */
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

/* ================= RENDER ================= */
async function renderLinks(raw){
    if(!raw)return;
    const normalized=normalizeDefang(raw);
    const defanged=defangValue(normalized);
    const type=detectType(normalized);

    document.getElementById("results").innerHTML="";

    if(["ipv4","ipv6","url","domain"].includes(type)){
        normalValue.innerHTML=`<strong>Normal:</strong> <span id="normalText" style="cursor:pointer;">${normalized}</span>`;
        defangedValue.innerHTML = `<strong>Defanged:</strong> <span id="defangText" style="cursor:pointer;">${defanged}</span>`;

        const normalSpan = document.getElementById("normalText");
        normalSpan.onclick = () => {
            navigator.clipboard.writeText(normalized);
            const original = normalSpan.innerText;
            normalSpan.innerText = "Copied!";
            setTimeout(() => normalSpan.innerText = original, 1000);
        };

        const defangSpan = document.getElementById("defangText");
        defangSpan.onclick = () => {
            navigator.clipboard.writeText(defanged);
            const original = defangSpan.innerText;
            defangSpan.innerText = "Copied!";
            setTimeout(() => defangSpan.innerText = original, 1000);
        };

        normalizedInfo.style.display="block";
    } else normalizedInfo.style.display="none";

    for (const src of sources[type]) {
        const p = await prepareData(normalized, type, src);
        const linkURL = src.url.replace("{data}", p);

        const a = document.createElement("a");
        a.href = linkURL;
        a.target = "_blank";
        a.className = "link-card";

        let domain = "";
        try { domain = new URL(linkURL).hostname; } catch {}

        const unlocked = isUnlocked(type, src.name);
        const lockIcon = unlocked ? "🔓" : "🔒";

        const lockBtn = `
            <span class="lock-btn" data-type="${type}" data-name="${src.name}">
                ${lockIcon}
            </span>
        `;

        const iconHTML = `<img src="https://www.google.com/s2/favicons?domain=${domain}" alt="${src.name}">`;

        a.innerHTML = `
            <div class="title">
                ${iconHTML}
                ${src.name}
                ${lockBtn}
            </div>
            <span class="url">${linkURL}</span>
        `;

        a.querySelector(".lock-btn").onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            const state = toggleUnlocked(type, src.name);
            e.target.textContent = state ? "🔓" : "🔒";
        };

        results.appendChild(a);
    }

}

/* ================= EVENTS ================= */
lookupBtn.onclick=()=>renderLinks(inputData.value.trim());
inputData.onkeypress=e=>{if(e.key==="Enter")renderLinks(inputData.value.trim());};

openAll.onclick = async () => {
    const raw = inputData.value.trim();
    if (!raw) return;

    const n = normalizeDefang(raw);
    const t = detectType(n);
    const prefs = loadOpenPrefs();

    for (const src of sources[t]) {
        if (src.openAll === false) continue;
        if (!prefs[`${t}|${src.name}`]) continue;

        const p = await prepareData(n, t, src);
        window.open(src.url.replace("{data}", p), "_blank");
    }
};

/* ================= BOOT SEQUENCE ================= */
const bootLines = [
    "[ OK ] Starting server..",
    "[ OK ] Initializing SOC Toolkit core",
    "[ OK ] Loading modules..",
    "[ OK ] Establishing secure environment",
    "[ OK ] SOC Toolkit ready",
    "[ OK ] Coded by Jimmy Bianco",
    "[ OK ] Redirecting to soctoolkit.com"
];

let line = 0;
const bootEl = document.getElementById("bootOutput");
const appEl = document.getElementById("app");
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

window.onload = bootSequence;

/* ================= THEME TOGGLE ================= */
const themeBtn = document.getElementById("themeToggle");

// Function to apply a theme
function applyTheme(theme) {
    document.body.classList.remove("hacker", "modern");
    document.body.classList.add(theme);

    // Trigger animation
    themeBtn.classList.remove("animate");
    void themeBtn.offsetWidth; // force reflow
    themeBtn.classList.add("animate");

    // Update icon
    if (theme === "modern") {
        themeBtn.textContent = "🌙";
    } else {
        themeBtn.textContent = "🔆";
    }

    localStorage.setItem("theme", theme);
}

// Apply saved theme on load
window.addEventListener("load", () => {
    const savedTheme = localStorage.getItem("theme") || "hacker";
    applyTheme(savedTheme);
});

// Change theme on button click
themeBtn.addEventListener("click", () => {
    const current = document.body.classList.contains("modern") ? "modern" : "hacker";
    const next = current === "hacker" ? "modern" : "hacker";
    applyTheme(next);
});

/* ================= UTC CLOCK ================= */
const utcClock = document.getElementById("utcClock");

function updateUTCClock() {
    const now = new Date();
    utcClock.textContent = now.toISOString().replace("T", " ").replace("Z", " UTC");
}

setInterval(updateUTCClock, 1000);
updateUTCClock();

/* ================= FOOTER CURRENT YEAR ================= */
document.getElementById("currentYear").textContent = new Date().getFullYear();
/* ================= FOOTER TOGGLE ================= */
document.querySelectorAll(".footer-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        const targetId = btn.dataset.target;
        const section = document.getElementById(targetId);

        // Close others
        document.querySelectorAll(".footer-section").forEach(sec => {
            if (sec !== section) sec.style.display = "none";
        });

        // Toggle current
        section.style.display =
            section.style.display === "block" ? "none" : "block";
    });
});
/* ================= END ================= */

















