<div align="center">

```
███████╗ ██████╗  ██████╗     ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝██╔═══██╗██╔════╝     ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
███████╗██║   ██║██║             ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
╚════██║██║   ██║██║             ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
███████║╚██████╔╝╚██████╗        ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
╚══════╝ ╚═════╝  ╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

### Un indicador, decenas de fuentes de inteligencia abierta — al instante.

[🇬🇧 English](README.md) · [🇪🇸 Español](README.es.md)

<br>

[![Demo](https://img.shields.io/badge/demo-soctoolkit.com-black?style=for-the-badge&labelColor=0d1117)](https://soctoolkit.com)
![Privacidad](https://img.shields.io/badge/PRIVACIDAD-100%25_CLIENT--SIDE-9acd00?style=for-the-badge&labelColor=0d1117)
![Stack](https://img.shields.io/badge/STACK-VANILLA_JS-9acd00?style=for-the-badge&labelColor=0d1117)

<br>

![Fuentes](https://img.shields.io/badge/FUENTES-90%2B-9acd00?style=flat-square&labelColor=0d1117)
![Tipos%20IoC](https://img.shields.io/badge/TIPOS_IOC-5-9acd00?style=flat-square&labelColor=0d1117)
![Backend](https://img.shields.io/badge/BACKEND-NINGUNO-9acd00?style=flat-square&labelColor=0d1117)
![Cuenta](https://img.shields.io/badge/CUENTA_REQUERIDA-NO-9acd00?style=flat-square&labelColor=0d1117)
![Autor](https://img.shields.io/badge/AUTOR-Jimmy_Bianco-9acd00?style=flat-square&labelColor=0d1117)

</div>

---

## 🧬 Descripción general

**SOC Toolkit** es una herramienta web gratuita, 100% client-side, pensada para analistas SOC, respondedores de incidentes y threat hunters. Pegás un indicador —dominio, IP, URL, hash o email— y la herramienta lo detecta automáticamente y lo resuelve al instante en enlaces listos para abrir hacia decenas de plataformas de reputación, sandboxing, DNS/WHOIS, dark web y OSINT. Sin cazar pestañas, sin memorizar la sintaxis de cada sitio.

No hay backend, no hay base de datos, no hay cuenta que crear. Todo corre en el navegador.

🔗 **Probalo en vivo:** [soctoolkit.com](https://soctoolkit.com)

<div align="center">

### 📊 EN NÚMEROS

| Fuentes | Categorías | Tipos de IoC | Backend | Setup |
|:---:|:---:|:---:|:---:|:---:|
| **90+** | **7** | **5** | **Ninguno** | **Abrir URL** |

</div>

---

## ⚡ Capacidades

| Módulo | Descripción |
|--------|-------------|
| 🎯 **Detección automática de IoC** | Reconoce dominios, IPv4/IPv6, URLs, hashes (MD5/SHA1/SHA256) y emails, y adapta las fuentes disponibles. Soporta además el parseo de múltiples IoCs pegados a la vez. |
| 🛡️ **Defanging / normalización** | Convierte el valor a formato `hxxp://evil[.]com` con un clic, listo para compartir en tickets y reportes. |
| 🔓 **Open Unlocked** | Abre en un solo clic todas las fuentes no restringidas para el indicador analizado. |
| 🧩 **Fuentes y herramientas personalizadas** | Agregá tus propias fuentes de lookup o feeds RSS, y reordená todo por drag & drop (Sortable.js). |
| 📰 **Panel de noticias de ciberseguridad** | Ticker y feed en vivo agregando RSS de The Hacker News, BleepingComputer, Securelist, Unit 42, CrowdStrike, Microsoft Security, The DFIR Report, entre otros — con filtros y refresco manual. |
| ⚙️ **Exportar / importar configuración** | Backup y restauración de tus fuentes, orden y tema en un único archivo JSON. |
| 🌓 **Theming & UX** | Tema claro/oscuro, fondo de partículas animado, boot screen estilo terminal y reloj UTC persistente. |
| 🔒 **Privacidad por diseño** | Ningún dato ingresado se envía, registra ni almacena en servidores propios. Todo el procesamiento ocurre localmente en el navegador. |

---

## 🗂️ Tipos de indicadores soportados

| Tipo | Ejemplo |
|---|---|
| Dominio | `evil.com` |
| IP (v4 / v6) | `8.8.8.8` |
| URL | `https://evil.com/payload` |
| Hash | MD5 / SHA1 / SHA256 |
| Email | `user@dominio.com` |

---

## 🌐 Fuentes integradas, por categoría

<details>
<summary><strong>Reputación & Threat Intelligence</strong></summary>

VirusTotal · AbuseIPDB · AlienVault OTX · IBM X-Force Exchange · Talos Reputation · GreyNoise · Censys · Shodan · ThreatFox · URLhaus · URLScan · URLVoid · Threat.Rip · Guardpot · SPUR (detección de VPN)

</details>

<details>
<summary><strong>Sandboxing de malware</strong></summary>

ANY.RUN · Hybrid Analysis · JOE Sandbox · Triage · MalShare · Valhalla (reglas SIGMA/YARA)

</details>

<details>
<summary><strong>DNS, WHOIS & Red</strong></summary>

WHOIS · SecurityTrails · DNSLytics · IPinfo · IPLocation · MyIP · RIPEstat · MXToolbox (SuperTool y Email Headers) · Netcraft · Web Check · Port Info

</details>

<details>
<summary><strong>Dark Web & Breaches</strong></summary>

Have I Been Pwned · HudsonRock (Infostealer, URL Discovery) · IntelX · Intelbase · Internxt Dark Web Monitor · SOCRadar Dark Web Report · WikiLeaks

</details>

<details>
<summary><strong>Malware, Living-off-the-Land & Referencia técnica</strong></summary>

GTFOBins · LOLBAS · LOTS Project · MalAPI · CyberChef · ExplainShell · NIST NVD · CVE.org · Exploit-DB · MITRE · Windows EventID Encyclopedia · Trend Micro Threat Encyclopedia

</details>

<details>
<summary><strong>Anti-fraude, phishing & ransomware</strong></summary>

Sucuri SiteCheck · CleanTalk (blacklist y malware scan) · Blacklist Checker · Phishing Checker · ClickFix Hunter · No More Ransom · Ransomware.live

</details>

<details>
<summary><strong>Otros / utilidades</strong></summary>

Wayback Machine (ver y guardar) · Google Translate · Nitter (búsqueda de tweets) · Browserling · Google Search

</details>

---

## 🚀 Cómo funciona

1. Pegá un dominio, IP, URL, hash o email en el campo de búsqueda.
2. SOC Toolkit detecta el tipo de indicador automáticamente.
3. Elegí una fuente individual o usá **Open Unlocked** para abrir todas de una.
4. Opcional: copiá el valor normalizado/defanged para tu reporte.
5. Personalizá fuentes, orden y tema desde el menú de ajustes ⚙️.

Sin instalación, sin build step:

```bash
git clone https://github.com/jimmybianco/SOCToolkit.git
cd SOCToolkit
open index.html   # o serví el sitio de forma estática, ej. `python3 -m http.server`
```

---

## 🧱 Stack técnico

- **HTML + CSS + JavaScript vanilla** — sin frameworks, sin build step.
- [Sortable.js](https://github.com/SortableJS/Sortable) para el reordenamiento drag & drop.
- `localStorage` para persistencia de configuración, fuentes personalizadas y preferencias.
- Sin backend ni base de datos: se despliega como sitio estático.

---

## 🔒 Privacidad

SOC Toolkit no recolecta, almacena ni transmite ningún dato ingresado por el usuario. Todo el procesamiento de indicadores ocurre localmente en el navegador. Se utiliza Google Analytics solo para estadísticas de uso anónimas y agregadas — nunca se comparte información ingresada por el usuario.

---

## 📬 Contacto

¿Sugerencias, bugs o ideas de nuevas fuentes? Escribí a **contact@soctoolkit.com** o abrí un issue en este repositorio.

Si te resulta útil, podés invitar un café ☕ → [buymeacoffee.com/jimmybianco](https://buymeacoffee.com/jimmybianco)

---

<div align="center">

Creado y mantenido por **[Jimmy Bianco](https://www.linkedin.com/in/jimmybianco)**

</div>
