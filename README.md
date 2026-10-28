# BSI TR-02102-1 & NIS-2 Local Crypto-Config Scanner (`bsi_pqc_check.py`)

[![Lizenz: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://www.python.org/)
[![BSI TR-02102-1](https://img.shields.io/badge/BSI-TR--02102--1%20%7C%202031-critical.svg)](https://www.bsi.bund.de)
[![NIS-2 Compliance](https://img.shields.io/badge/NIS--2-%C2%A7%2030%20BSIG-orange.svg)](https://kenanerorr404.github.io/de-compliance-kompass/pqc-nis2-rechner.html)

Ein leichtgewichtiger, **Zero-Dependency Open-Source CLI-Scanner** (100 % Python Standard Library) für Linux-Administratoren, CISOs, IT-Grundschutz-Praktiker und DiGA-/KRITIS-Hersteller. Das Tool prüft lokale SSH-Daemon-Konfigurationen (`sshd_config`), OpenSSL-/TLS-Systemrichtlinien (`openssl.cnf`) und X.509-Zertifikate automatisiert gegen das **BSI-Auslaufszenario 2031 für klassische asymmetrische Kryptographie (RSA-2048, klassisches ECDSA/ECDH)** sowie die **NIS-2 Kryptographie Anforderungen (§ 30 Abs. 2 Nr. 8 BSIG)**.

---

## 🎯 Warum eine BSI TR-02102-1 Checkliste & lokale Bestandsaufnahme (CBOM) jetzt kritisch ist

Mit dem Inkrafttreten des **NIS-2-Umsetzungsgesetzes (NIS2UmsuCG)** und den verschärften Vorgaben der **BSI Technischen Richtlinie TR-02102-1 / TR-02102-2 / TR-02102-4** stehen IT-Verantwortliche in Deutschland vor zwei konkreten regulatorischen Deadlines:

1. **Abkündigung von RSA-2048 & klassischer ECC (Frist 2031):** Gemäß BSI TR-02102-1 sind asymmetrische Verfahren unterhalb von 3072 Bit (insbesondere `RSA-2048`) nur noch zeitlich befristet zulässig. Für langfristig schützenswerte Daten (Gesundheitsdaten/DiGA, KRITIS, Finanzsektor, Industriegeheimnisse) gilt aufgrund von **"Store Now, Decrypt Later" (SNDL)** bereits heute die Pflicht zur Planung hybrider **Post-Quantum-Kryptographie (PQC)** wie `ML-KEM-768` (FIPS 203) und `ML-DSA` (FIPS 204).
2. **NIS-2 Kryptographie Anforderungen & Geschäftsführerhaftung (§ 30 & § 38 BSIG):** Besonders wichtige und wichtige Einrichtungen müssen ein dokumentiertes Konzept für den Einsatz kryptographischer Verfahren sowie ein **Krypto-Inventar (Cryptographic Bill of Materials – CBOM)** vorweisen. Bei Verstößen greift die persönliche Organhaftung der Geschäftsleitung (§ 38 BSIG).

> **💡 Direkt im Browser prüfen:** Nutzen Sie ergänzend unseren kostenlosen, clientseitigen **[BSI PQC & NIS-2 Bußgeld- und Migrations-Rechner](https://kenanerorr404.github.io/de-compliance-kompass/pqc-nis2-rechner.html)** für eine sofortige kaufmännische und regulatorische Risikobewertung nach § 60 BSIG.

---

## ⚙️ Features des CLI-Scanners

* **Keine Drittanbieter-Abhängigkeiten:** Läuft auf jedem Debian, Ubuntu, RHEL, SUSE oder Alpine System mit Python 3 (`stdlib` only) und lokalem `openssl` / `ssh-keygen`.
* **SSH-Audit nach BSI TR-02102-4:** Erkennt veraltete Algorithmen (`ssh-rsa`, `ecdsa-sha2-nistp256`, SHA-1 Diffie-Hellman), prüft lokale `/etc/ssh/ssh_host_*_key.pub` Schlüssellängen und bewertet hybride PQC-Schlüsselaustauschverfahren (`mlkem768x25519-sha256`, `sntrup761x25519-sha512@openssh.com`).
* **OpenSSL & TLS-Richtlinien nach BSI TR-02102-2:** Prüft die installierte OpenSSL-Runtime auf PQC-Readiness (OpenSSL >= 3.2/3.5 bzw. OQS-Provider) und analysiert `MinProtocol` sowie `CipherString` / `SECLEVEL` in `/etc/ssl/openssl.cnf`.
* **X.509-Zertifikats-Scanner:** Analysiert lokale `.pem`- und `.crt`-Zertifikate auf `RSA < 3072 Bit`, klassische ECDSA-Kurven und unsichere Signatur-Hashes (`SHA-1`, `MD5`).
* **JSON-Export für Ihr CBOM:** Exportiert auf Wunsch alle Befunde per `--json-out` als strukturierte JSON-Datei für Ihre **BSI TR-02102-1 Checkliste** oder Ihr ISMS nach ISO 27001 / IT-Grundschutz.

---

## 🚀 Schnellstart & Installation (pipx, pip oder Zero-Install One-Liner)

### Option A: Sofort-Ausführung oder Installation via `pipx` / `pip` (v1.3.0+)

```bash
# Direkt in isolierter Umgebung ausführen (ohne permanente Installation):
pipx run git+https://github.com/KenanErorr404/bsi-tr02102-pqc-audit-cli.git

# Oder als CLI-Befehl `bsi-pqc-check` installieren:
pip install git+https://github.com/KenanErorr404/bsi-tr02102-pqc-audit-cli.git
bsi-pqc-check --json-out cbom_findings.json
```

### Option B: Zero-Install `curl` One-Liner

Direkt ohne Repository-Klon auf jedem Linux-System ausführen (erzeugt neben der Terminal-Tabelle automatisch den lokalen Prüfbericht `bsi-pqc-audit-report.html`):

```bash
curl -sSL https://raw.githubusercontent.com/KenanErorr404/bsi-tr02102-pqc-audit-cli/main/bsi_pqc_check.py | python3 -
```

### Option C: Git-Clone für lokale Anpassungen & JSON/HTML-Audit-Exporte

```bash
git clone https://github.com/kenanerorr404/bsi-tr02102-pqc-audit-cli.git
cd bsi-tr02102-pqc-audit-cli
chmod +x bsi_pqc_check.py

# Standard-Scan auf dem lokalen Linux-System ausführen (schreibt bsi-pqc-audit-report.html):
python3 bsi_pqc_check.py

# Optional: Spezifische Konfigurationspfade & JSON-Export für das Audit-Dossier:
python3 bsi_pqc_check.py \
  --ssh-config /etc/ssh/sshd_config \
  --openssl-config /etc/ssl/openssl.cnf \
  --cert-path /etc/ssl/certs \
  --max-certs 10 \
  --json-out cbom_findings.json
```

---

## 🤖 Integration als GitHub Action in CI/CD-Pipelines (`.github/workflows/bsi-pqc-audit.yml`)

Für automatisierte DevSecOps-Prüfungen nach **BSI TR-02102-1**, **BSI TR-03185 (Secure SDLC)** und **NIS-2 (§ 30 BSIG)** kann dieses Repository direkt als Composite GitHub Action eingebunden werden. Die Action schreibt eine vollständige Prüftabelle samt CBOM-Empfehlungen direkt in die **GitHub Actions Job Summary (`$GITHUB_STEP_SUMMARY`)**:

```yaml
name: BSI TR-02102-1 & NIS-2 PQC Crypto Audit

on:
  push:
    branches: [ "main" ]
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # Wöchentlicher NIS-2 / CBOM Compliance-Check

jobs:
  bsi-pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run BSI TR-02102-1 & NIS-2 PQC Scanner
        uses: KenanErorr404/bsi-tr02102-pqc-audit-cli@v1.1.0
        with:
          ssh-config: "/etc/ssh/sshd_config"
          openssl-config: "/etc/ssl/openssl.cnf"
          cert-path: "/etc/ssl/certs"
          max-certs: "8"
          json-out: "cbom_findings.json"

      - name: Upload CBOM Audit Artifact (NIS-2 § 30 BSIG Nachweis)
        uses: actions/upload-artifact@v4
        with:
          name: bsi-tr02102-cbom-findings
          path: cbom_findings.json
```

---

## 📋 Integrierte BSI TR-02102-1 Checkliste (Referenzmatrix)

| Einsatzbereich | Klassischer Standard (Auslauf / Risiko) | BSI TR-02102 Empfehlung (Übergang & Zielbild 2031+) | Regulatorische Referenz |
| :--- | :--- | :--- | :--- |
| **TLS 1.3 Schlüsselaustausch** | Klassisches ECDHE (`secp256r1`, `X25519` allein) | **Hybrid-PQC KEM:** `X25519MLKEM768` oder `secp256r1MLKEM768` | BSI TR-02102-2 / § 30 BSIG |
| **SSH Key Exchange (KEX)** | `diffie-hellman-group14-sha1`, klassisches ECDH | `mlkem768x25519-sha256`, `sntrup761x25519-sha512@openssh.com` | BSI TR-02102-4 |
| **X.509 / Asymmetrische Schlüssel** | `RSA-2048` (Fristende!), klassische `ECDSA P-256` | Mind. `RSA-3072` (kurzfristig) bzw. Hybrid-Signaturen mit `ML-DSA` / `SLH-DSA` | BSI TR-02102-1 |
| **Krypto-Agilität & Inventar** | Manuelle Ad-hoc-Zertifikatsverwaltung | Vollständige **CBOM (Cryptographic Bill of Materials)** & Krypto-Richtlinie | NIS-2 Art. 21 / § 30 BSIG |
| **Sichere Software-Updates (DiGA/CRA)** | Unstrukturierte Patch-Prozesse bei Krypto-Updates | Dokumentierte **Update-Klassifizierungsmatrix** ohne Rezertifizierungsverlust | **BSI TR-03185 Vorlage** / TR-03185-2 |

---

## 📦 Weiterführende Compliance-Werkzeuge & Audit-Vorlagen

Für B2B-Teams, Datenschutzbeauftragte, CISOs und Auditoren, die über den technischen CLI-Scan hinaus sofort prüfungsfähige Nachweisdokumente für BSI-, ISO-27001-, DiGA- (BfArM) oder NIS-2-Prüfungen benötigen:

1. **[Kostenloser Web-Rechner: BSI PQC & NIS-2 Risiko- und Bußgeld-Kalkulator](https://kenanerorr404.github.io/de-compliance-kompass/pqc-nis2-rechner.html)**
   * Berechnet in 60 Sekunden Ihren PQC-Migrations-Score, das "Store-Now-Decrypt-Later"-Risiko und den NIS-2-Bußgeldrahmen nach § 60 BSIG (100 % lokal im Browser).
2. **[BSI TR-02102 PQC & Krypto-Inventar (CBOM) Migrations-Pack](https://kenanghalioun.gumroad.com/l/wcqysh)**
   * Enthält: Fertige **CBOM-Excel/CSV-Vorlage**, **NIS-2 Kryptographie-Richtlinie (§ 30 BSIG)**, **Management-Haftungs-Vorlage (§ 38 BSIG)** und den **PQC-Migrationsplan 2026–2031**.
3. **[BSI TR-03185Vorlage & Audit-Readiness-Pack (Sichere Software-Updates ohne Rezertifizierung)](https://kenanghalioun.gumroad.com/l/juznqz)**
   * Enthält: **Update-Klassifizierungsmatrix (Major/Minor/Security Patch)**, **SBOM/VEX-Freigabe-Checkliste** und **Herstellererklärung nach BSI TR-03185-2** (ideal für DiGA-Hersteller, MedTech & CRA-Compliance).

---

## 📄 Lizenz

Veröffentlicht unter der **MIT-Lizenz**. Kostenlos nutzbar für interne Sicherheitsaudits, Penetrationstests und kommerzielle ISMS-Prüfungen.
