/* ============== SOURCES ============== */
const sources = {
    ipv4: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}"},
        {name:"Blackist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"}
    ],
    ipv6: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}"},
        {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}"},
        {name:"Blackist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
        {name:"Shodan", url:"https://www.shodan.io/search?query={data}"},
        {name:"Censys", url:"https://search.censys.io/hosts/{data}"},
        {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}"},
        {name:"IPLocation", url:"https://iplocation.io/ip/{data}"}
    ],
    url: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/url/{data}", needsHash:true, encode:true},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/url/{data}",encode:false},
        {name:"URLScan", url:"https://urlscan.io/search/#{data}", encode:false, usesDomain:true},
        {name:"Blackist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", usesDomain:true, openAll:false},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}",encode:false, openAll:false},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}", openAll:false},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}", usesDomain:true, openAll:false},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}", usesDomain:true},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false, openAll:false},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false, openAll:false},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false, openAll:false}
    ],
    domain: [
        {name:"VirusTotal", url:"https://www.virustotal.com/gui/domain/{data}"},
        {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}"},
        {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/url/{data}"},
        {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/url/{data}"},
        {name:"URLScan", url:"https://urlscan.io/search/#{data}", encode:false},
        {name:"Blackist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:true, encode:false},
        {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", openAll:false},
        {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}", openAll:false},
        {name:"Web Check", url:"https://web-check.xyz/check/{data}", openAll:false},
        {name:"SecurityTrails - DNS", url:"https://securitytrails.com/domain/{data}", openAll:false},
        {name:"WHOIS", url:"https://www.whois.com/whois/{data}"},
        {name:"Phishing Checker", url:"https://phishing.finsin.cl/list.php", encode:false, openAll:false},
        {name:"Browserling", url:"https://www.browserling.com/browse/win10/chrome138/{data}", encode:false, openAll:false},
        {name:"AnyRun", url:"https://app.any.run/safe/{data}", encode:false, openAll:false}
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
    ],
    email: [
        {name:"Have I Been Pwned", url:"https://haveibeenpwned.com/unifiedsearch/{data}", usesDomain:false},
        {name:"Intelbase", url:"https://intelbase.is/", usesDomain:true, encode:false},
        {name:"Blackist Checker", url:"https://blacklistchecker.com/check?input={data}", usesDomain:false, encode:false},
    ],
    text: [
        {name:"Google", url:"https://www.google.com/search?q={data}", openAll:false},
        {name:"Translate", url:"https://translate.google.com/?sl=auto&tl=en&text={data}&op=translate", openAll:false},
        {name:"LOLBAS", url:"https://lolbas-project.github.io/#{data}", encode:false, openAll:false},
        {name:"GTFOBins", url:"https://gtfobins.github.io/#{data}", encode:false, openAll:false},
        {name:"Mitre", url:"https://www.google.com/search?q=inurl:attack.mitre.org+{data}", openAll:false},
        {name:"NIST NVD", url:"https://nvd.nist.gov/vuln/search#/nvd/home?keyword={data}&resultType=records", openAll:false},
        {name:"CVE ORG", url:"https://www.cve.org/CVERecord?id={data}", openAll:false},
        {name:"Exploit DB", url:"https://www.exploit-db.com/search?q={data}", openAll:false},
        {name:"Windows EventID", url:"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={data}", openAll:false},
        {name:"Microsoft ErrorCode", url:"https://login.microsoftonline.com/error", encode:false, openAll:false},
        {name:"CyberChef", url:"https://gchq.github.io/CyberChef/", encode:false, openAll:false},
        {name:"MXToolBox - EmailHeaders", url:"https://mxtoolbox.com/EmailHeaders.aspx", encode:false, openAll:false},
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

/* ================= NORMALIZATION ================= */
async function prepareData(input,type,src){
    let data=input;
    if(type==="url"&&src.needsHash)data=await sha256(input);
    if(src.usesDomain){
        if(type==="email")data=emailDomain(input);
        else if(type==="url")data=urlDomain(input);
    }
    if(src.encode!==false)data=encodeURIComponent(data);
    return data;
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
        defangedValue.innerHTML = `<strong>Defanged:</strong> <span id="defangText">${defanged}</span>`;

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

    for(const src of sources[type]){
        const p = await prepareData(normalized,type,src);
        const linkURL = src.url.replace("{data}",p);

        const a = document.createElement("a");
        a.href = linkURL;
        a.target = "_blank";
        a.className = "link-card";

        // Obtener favicon automático
        let domain = "";
        try {
            domain = new URL(linkURL).hostname;
        } catch {}
        const iconHTML = `<img src="https://www.google.com/s2/favicons?domain=${domain}" alt="${src.name}">`;

        a.innerHTML = `<div class="title">${iconHTML}${src.name}</div><span class="url">${linkURL}</span>`;
        results.appendChild(a);
    }
}

/* ================= EVENTS ================= */
lookupBtn.onclick=()=>renderLinks(inputData.value.trim());
inputData.onkeypress=e=>{if(e.key==="Enter")renderLinks(inputData.value.trim());};

openAll.onclick=async()=>{
    const raw=inputData.value.trim();
    if(!raw)return;
    const n=normalizeDefang(raw);
    const t=detectType(n);
    for(const src of sources[t]){
        if(src.openAll===false)continue;
        const p=await prepareData(n,t,src);
        window.open(src.url.replace("{data}",p),"_blank");
    }
};

const bootLines = [
    "[ OK ] Starting server..",
    "[ OK ] Initializing SOC Toolkit core",
    "[ OK ] Loading modules..",
    "[ OK ] Initializing language engine",
    "[ OK ] Initializing routing",
    "[ OK ] Checking service availability",
    "[ OK ] Establishing secure environment",
    "[ OK ] Coded by Jimmy Bianco",
    "[ OK ] SOC Toolkit ready",
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

// Función para aplicar tema
function applyTheme(theme) {
    document.body.classList.remove("hacker", "modern");
    document.body.classList.add(theme);
    localStorage.setItem("theme", theme);
}

// Al cargar la página, aplicamos el tema guardado o por defecto
window.addEventListener("load", () => {
    const savedTheme = localStorage.getItem("theme") || "hacker";
    applyTheme(savedTheme);
});

// Al hacer clic en el botón, alternamos tema
themeBtn.addEventListener("click", () => {
    const current = document.body.classList.contains("hacker") ? "hacker" : "modern";
    const next = current === "hacker" ? "modern" : "hacker";
    applyTheme(next);
});
