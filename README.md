<div align="center">

```
███████╗ ██████╗  ██████╗     ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝     ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║             ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
╚════██║██║   ██║██║             ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
███████║╚██████╔╝╚██████╗        ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
╚══════╝ ╚═════╝  ╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

### One indicator in, dozens of open-source intel sources out — instantly.

[🇬🇧 English](README.md) · [🇪🇸 Español](README.es.md)

<br>

[![Live](https://img.shields.io/badge/demo-soctoolkit.com-black?style=for-the-badge&labelColor=0d1117)](https://soctoolkit.com)
![Privacy](https://img.shields.io/badge/PRIVACY-100%25_CLIENT--SIDE-9acd00?style=for-the-badge&labelColor=0d1117)
![Stack](https://img.shields.io/badge/STACK-VANILLA_JS-9acd00?style=for-the-badge&labelColor=0d1117)

<br>

![Sources](https://img.shields.io/badge/SOURCES-90%2B-9acd00?style=flat-square&labelColor=0d1117)
![IoC%20Types](https://img.shields.io/badge/IOC_TYPES-5-9acd00?style=flat-square&labelColor=0d1117)
![Backend](https://img.shields.io/badge/BACKEND-NONE-9acd00?style=flat-square&labelColor=0d1117)
![Account](https://img.shields.io/badge/ACCOUNT_NEEDED-NO-9acd00?style=flat-square&labelColor=0d1117)
![Author](https://img.shields.io/badge/AUTHOR-Jimmy_Bianco-9acd00?style=flat-square&labelColor=0d1117)

</div>

---

## 🧬 Overview

**SOC Toolkit** is a free, browser-based utility built for SOC analysts, incident responders, and threat hunters. Paste in an indicator — domain, IP, URL, hash, or email — and it's auto-detected and instantly resolved into ready-to-open links across dozens of reputation, sandboxing, DNS/WHOIS, dark web, and OSINT platforms. No tab-hunting, no memorizing each site's URL syntax.

There is no backend, no database, and no account to create. Everything runs client-side, in your browser.

🔗 **Try it live:** [soctoolkit.com](https://soctoolkit.com)

<div align="center">

### 📊 AT A GLANCE

| Sources | Categories | IoC types | Backend | Setup |
|:---:|:---:|:---:|:---:|:---:|
| **90+** | **7** | **5** | **None** | **Open URL** |

</div>

---

## ⚡ Capabilities

| Module | Description |
|--------|-------------|
| 🎯 **IoC auto-detection** | Recognizes domains, IPv4/IPv6, URLs, hashes (MD5/SHA1/SHA256) and emails, and adapts available sources accordingly. Also parses multiple IoCs pasted at once. |
| 🛡️ **Defang / normalize** | One-click conversion to `hxxp://evil[.]com` style, safe for pasting into tickets and reports. |
| 🔓 **Open Unlocked** | Opens every unrestricted source for the current indicator in one click. |
| 🧩 **Custom tools & feeds** | Add your own lookup sources or RSS feeds, and reorder everything via drag & drop (Sortable.js). |
| 📰 **Security news feed** | Live ticker and feed aggregating RSS from The Hacker News, BleepingComputer, Securelist, Unit 42, CrowdStrike, Microsoft Security, The DFIR Report, and more — filterable, with manual refresh. |
| ⚙️ **Export / import config** | Back up and restore your sources, ordering, and theme as a single JSON file. |
| 🌓 **Theming & UX** | Light/dark theme, animated particle background, terminal-style boot screen, and a persistent UTC clock. |
| 🔒 **Privacy by design** | No submitted data is sent to, logged by, or stored on any server. Everything runs locally in the browser. |

---

## 🗂️ Supported IoC types

| Type | Example |
|---|---|
| Domain | `evil.com` |
| IP (v4 / v6) | `8.8.8.8` |
| URL | `https://evil.com/payload` |
| Hash | MD5 / SHA1 / SHA256 |
| Email | `user@domain.com` |

---

## 🌐 Integrated sources, by category

<details>
<summary><strong>Reputation & Threat Intelligence</strong></summary>

VirusTotal · AbuseIPDB · AlienVault OTX · IBM X-Force Exchange · Talos Reputation · GreyNoise · Censys · Shodan · ThreatFox · URLhaus · URLScan · URLVoid · Threat.Rip · Guardpot · SPUR (VPN detection)

</details>

<details>
<summary><strong>Malware Sandboxing</strong></summary>

ANY.RUN · Hybrid Analysis · JOE Sandbox · Triage · MalShare · Valhalla (SIGMA/YARA rules)

</details>

<details>
<summary><strong>DNS, WHOIS & Network</strong></summary>

WHOIS · SecurityTrails · DNSLytics · IPinfo · IPLocation · MyIP · RIPEstat · MXToolbox (SuperTool & Email Headers) · Netcraft · Web Check · Port Info

</details>

<details>
<summary><strong>Dark Web & Breaches</strong></summary>

Have I Been Pwned · HudsonRock (Infostealer, URL Discovery) · IntelX · Intelbase · Internxt Dark Web Monitor · SOCRadar Dark Web Report · WikiLeaks

</details>

<details>
<summary><strong>Malware, Living-off-the-Land & Reference</strong></summary>

GTFOBins · LOLBAS · LOTS Project · MalAPI · CyberChef · ExplainShell · NIST NVD · CVE.org · Exploit-DB · MITRE · Windows EventID Encyclopedia · Trend Micro Threat Encyclopedia

</details>

<details>
<summary><strong>Anti-fraud, Phishing & Ransomware</strong></summary>

Sucuri SiteCheck · CleanTalk (blacklist & malware scan) · Blacklist Checker · Phishing Checker · ClickFix Hunter · No More Ransom · Ransomware.live

</details>

<details>
<summary><strong>Other / Utilities</strong></summary>

Wayback Machine (view & save) · Google Translate · Nitter (tweet search) · Browserling · Google Search

</details>

---

## 🚀 How it works

1. Paste a domain, IP, URL, hash, or email into the search box.
2. SOC Toolkit auto-detects the indicator type.
3. Click an individual source, or hit **Open Unlocked** to open them all at once.
4. Optionally copy the normalized/defanged value for your report.
5. Customize sources, ordering, and theme from the settings menu ⚙️.

No install, no build step:

```bash
git clone https://github.com/jimmybianco/SOCToolkit.git
cd SOCToolkit
open index.html   # or serve statically, e.g. `python3 -m http.server`
```

---

## 🧱 Tech stack

- **Vanilla HTML + CSS + JavaScript** — no framework, no build step.
- [Sortable.js](https://github.com/SortableJS/Sortable) for drag & drop reordering.
- `localStorage` for persisting configuration, custom sources, and preferences.
- No backend, no database — deployable as a static site.

---

## 🔒 Privacy

SOC Toolkit does not collect, store, or transmit any data entered by the user. All indicator processing happens locally in the browser. Google Analytics is used only for anonymous, aggregated usage statistics — no user-submitted data is ever shared with it.

---

## 📬 Contact

Suggestions, bugs, or ideas for new sources? Email **contact@soctoolkit.com** or open an issue on this repository.

If you find it useful, consider buying a coffee ☕ → [buymeacoffee.com/jimmybianco](https://buymeacoffee.com/jimmybianco)

---

<div align="center">

Built and maintained by **[Jimmy Bianco](https://www.linkedin.com/in/jimmybianco)**

</div>
