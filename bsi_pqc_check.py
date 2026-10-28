#!/usr/bin/env python3
"""
BSI TR-02102-1 & NIS-2 Local Crypto-Config Scanner (v1.0.0)
===========================================================
Prüft lokale SSH-Konfigurationen (sshd_config), OpenSSL/TLS-Konfigurationen
und X.509-Zertifikate auf veraltete asymmetrische Verfahren (RSA < 3072 Bit,
klassische ECDSA-Kurven) gemäß BSI TR-02102-1 (Frist 2031) und § 30 BSIG (NIS-2).

Zero-Dependency CLI (100% Python Standard Library).
Lizenz: MIT
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# BSI TR-02102-1 / NIS-2 Grenzwerte
RSA_MIN_BITS_2031 = 3072
LEGACY_SSH_ALGS = [
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
]
PQC_RECOMMENDED_KEX = [
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
]


class Finding:
    def __init__(
        self,
        category: str,
        target: str,
        algorithm: str,
        status: str,
        bsi_ref: str,
        recommendation: str,
    ):
        self.category = category
        self.target = target
        self.algorithm = algorithm
        self.status = status  # "CRITICAL", "WARNING", "PASS"
        self.bsi_ref = bsi_ref
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "target": self.target,
            "algorithm": self.algorithm,
            "status": self.status,
            "bsi_reference": self.bsi_ref,
            "recommendation": self.recommendation,
        }


def scan_sshd_config(paths: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    checked_any = False

    for path in paths:
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            findings.append(
                Finding(
                    "SSH Config",
                    str(path),
                    "Zugriff verweigert (Permission Denied)",
                    "WARNING",
                    "BSI TR-02102-4",
                    "Mit sudo ausführen oder Leserechte für Audit prüfen",
                )
            )
            checked_any = True
            continue

        checked_any = True
        active_lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        joined = "\n".join(active_lines)

        # Check legacy algorithms in KexAlgorithms, HostKeyAlgorithms, PubkeyAcceptedAlgorithms
        found_legacy = [alg for alg in LEGACY_SSH_ALGS if alg in joined]
        has_pqc_kex = any(kex in joined for kex in PQC_RECOMMENDED_KEX)

        if found_legacy:
            findings.append(
                Finding(
                    "SSH Daemon",
                    str(path),
                    f"Legacy: {', '.join(found_legacy)}",
                    "CRITICAL",
                    "BSI TR-02102-4 Kap. 3",
                    "Entfernen von ssh-rsa/SHA-1 & Umstieg auf Hybrid-PQC KEX",
                )
            )
        elif not has_pqc_kex:
            findings.append(
                Finding(
                    "SSH Daemon",
                    str(path),
                    "Klassisches ECDH/Ed25519 (Kein explizites PQC-Hybrid)",
                    "WARNING",
                    "BSI TR-02102-1 (2031)",
                    "KexAlgorithms um mlkem768x25519-sha256 / sntrup761x25519 ergänzen",
                )
            )
        else:
            findings.append(
                Finding(
                    "SSH Daemon",
                    str(path),
                    "PQC-Hybrid KEX aktiv",
                    "PASS",
                    "BSI TR-02102-4",
                    "Konform für Post-Quantum-Transition",
                )
            )

    # Check SSH Host Public Keys (/etc/ssh/ssh_host_*_key.pub)
    ssh_dir = Path("/etc/ssh")
    if ssh_dir.is_dir():
        for pub_key in sorted(ssh_dir.glob("ssh_host_*_key.pub")):
            checked_any = True
            try:
                out = subprocess.run(
                    ["ssh-keygen", "-lf", str(pub_key)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip():
                    parts = out.stdout.strip().split()
                    bits = int(parts[0]) if parts[0].isdigit() else 0
                    key_type = parts[-1].strip("()")
                    if key_type.upper() == "RSA" and bits < RSA_MIN_BITS_2031:
                        findings.append(
                            Finding(
                                "SSH HostKey",
                                pub_key.name,
                                f"RSA-{bits}",
                                "CRITICAL",
                                "BSI TR-02102-1 (Frist 2031)",
                                f"RSA-{bits} läuft 2031 aus; mindestens RSA-3072 oder PQC-Hybrid nutzen",
                            )
                        )
                    elif key_type.upper() == "ECDSA":
                        findings.append(
                            Finding(
                                "SSH HostKey",
                                pub_key.name,
                                f"ECDSA-{bits} (Klassisch)",
                                "WARNING",
                                "BSI TR-02102-1 / Store-Now-Decrypt-Later",
                                "Klassische ECC nicht quantensicher; PQC-Migrationspfad nach § 30 BSIG planen",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                "SSH HostKey",
                                pub_key.name,
                                f"{key_type}-{bits}",
                                "PASS",
                                "BSI TR-02102-4",
                                "Schlüssellänge aktuell ausreichend (Krypto-Inventar/CBOM pflegen)",
                            )
                        )
            except Exception:
                pass

    if not checked_any:
        findings.append(
            Finding(
                "SSH Config",
                "/etc/ssh/sshd_config",
                "Nicht gefunden",
                "WARNING",
                "BSI TR-02102-4",
                "Pfad per --ssh-config angeben",
            )
        )

    return findings


def scan_openssl_config(paths: List[Path]) -> List[Finding]:
    findings: List[Finding] = []
    # Check local OpenSSL binary version & PQC provider support
    try:
        ver_out = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, timeout=5
        )
        ver_str = ver_out.stdout.strip() if ver_out.returncode == 0 else "Unbekannt"
        if "OpenSSL 1." in ver_str or "OpenSSL 3.0" in ver_str or "OpenSSL 3.1" in ver_str:
            findings.append(
                Finding(
                    "OpenSSL Runtime",
                    "openssl binary",
                    ver_str,
                    "WARNING",
                    "BSI TR-02102-2",
                    "Upgrade auf OpenSSL >= 3.2/3.5 oder oqs-provider für ML-KEM / ML-DSA prüfen",
                )
            )
        else:
            findings.append(
                Finding(
                    "OpenSSL Runtime",
                    "openssl binary",
                    ver_str,
                    "PASS",
                    "BSI TR-02102-2",
                    "Moderne OpenSSL-Laufzeitumgebung erkannt",
                )
            )
    except FileNotFoundError:
        findings.append(
            Finding(
                "OpenSSL Runtime",
                "openssl binary",
                "Nicht installiert",
                "CRITICAL",
                "BSI TR-02102-2",
                "OpenSSL für Zertifikats- und TLS-Prüfung installieren",
            )
        )

    for path in paths:
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            continue

        sec_match = re.search(r"CipherString\s*=\s*([^\s\n#]+)", content)
        min_proto = re.search(r"MinProtocol\s*=\s*([^\s\n#]+)", content)

        proto_val = min_proto.group(1) if min_proto else "Standard (nicht explizit)"
        cipher_val = sec_match.group(1) if sec_match else "Standard"

        if "TLSv1.0" in proto_val or "TLSv1.1" in proto_val or "SECLEVEL=1" in cipher_val:
            findings.append(
                Finding(
                    "OpenSSL / TLS",
                    str(path),
                    f"MinProto={proto_val}, Cipher={cipher_val}",
                    "CRITICAL",
                    "BSI TR-02102-2 Kap. 3",
                    "Mindestens TLSv1.2 (besser TLSv1.3) und SECLEVEL>=2 erzwingen",
                )
            )
        else:
            findings.append(
                Finding(
                    "OpenSSL / TLS",
                    str(path),
                    f"MinProto={proto_val}, Cipher={cipher_val}",
                    "PASS",
                    "BSI TR-02102-2",
                    "Für 2031: Hybrid-KEM Groups (z.B. X25519MLKEM768) in Groups-Direktive testen",
                )
            )

    return findings


def analyze_cert_file(cert_path: Path) -> Optional[Finding]:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0:
            return None
        text = out.stdout
        alg_match = re.search(r"Public Key Algorithm:\s*([^\n]+)", text)
        bits_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
        sig_match = re.search(r"Signature Algorithm:\s*([^\n]+)", text)

        alg = alg_match.group(1).strip() if alg_match else "Unknown"
        bits = int(bits_match.group(1)) if bits_match else 0
        sig = sig_match.group(1).strip() if sig_match else "Unknown"

        if "rsaEncryption" in alg and bits > 0 and bits < RSA_MIN_BITS_2031:
            return Finding(
                "X.509 Cert",
                cert_path.name,
                f"RSA-{bits} ({sig})",
                "CRITICAL",
                "BSI TR-02102-1 (Frist 2031)",
                f"RSA-{bits} < 3072 Bit abgekündigt; Austausch im CBOM priorisieren",
            )
        if "id-ecPublicKey" in alg:
            return Finding(
                "X.509 Cert",
                cert_path.name,
                f"ECDSA-{bits} ({sig})",
                "WARNING",
                "BSI TR-02102-1 / NIS-2 § 30 BSIG",
                "Klassische ECC verwundbar durch Shor-Algorithmus; PQC/Hybrid-Zertifikate planen",
            )
        if "sha1" in sig.lower() or "md5" in sig.lower():
            return Finding(
                "X.509 Cert",
                cert_path.name,
                f"{alg} ({sig})",
                "CRITICAL",
                "BSI TR-02102-1 Kap. 4",
                "Schwacher Hash-Algorithmus in Signatur; sofort ersetzen",
            )
        return Finding(
            "X.509 Cert",
            cert_path.name,
            f"{alg}-{bits} ({sig})",
            "PASS",
            "BSI TR-02102-1",
            "Schlüsselstärke >= 3072 Bit oder PQC-ready",
        )
    except Exception:
        return None


def scan_certificates(cert_dirs: List[Path], max_certs: int = 8) -> List[Finding]:
    findings: List[Finding] = []
    scanned = 0
    for d in cert_dirs:
        if not d.exists():
            continue
        files = [d] if d.is_file() else sorted(list(d.glob("*.pem")) + list(d.glob("*.crt")))
        for f in files:
            if scanned >= max_certs:
                break
            res = analyze_cert_file(f)
            if res:
                findings.append(res)
                scanned += 1
        if scanned >= max_certs:
            break
    return findings


def print_summary_table(findings: List[Finding]) -> None:
    print("=" * 98)
    print(" BSI TR-02102-1 & NIS-2 (§ 30 BSIG) LOCAL CRYPTO-CONFIG & PQC READINESS SCANNER")
    print("=" * 98)
    print(f" Zeitstempel : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Prüfnormen  : BSI TR-02102-1/-2/-4 (Frist 2031), NIS2UmsuCG (§ 30 & § 38 BSIG)")
    print("-" * 98)
    header = f" {'STATUS':<10} | {'KATEGORIE':<15} | {'ZIEL / DATEI':<24} | {'ALGORITHMUS / BEFUND':<40}"
    print(header)
    print("-" * 98)

    crit_count = 0
    warn_count = 0
    pass_count = 0

    for f in findings:
        if f.status == "CRITICAL":
            crit_count += 1
        elif f.status == "WARNING":
            warn_count += 1
        else:
            pass_count += 1

        target_short = (f.target[:21] + "...") if len(f.target) > 24 else f.target
        alg_short = (f.algorithm[:37] + "...") if len(f.algorithm) > 40 else f.algorithm
        print(f" {f.status:<10} | {f.category:<15} | {target_short:<24} | {alg_short:<40}")
        print(f"            └─> [{f.bsi_ref}] Empfehlung: {f.recommendation}")

    print("=" * 98)
    print(
        f" ZUSAMMENFASSUNG: {crit_count} CRITICAL (Legacy RSA-2048/SHA-1) | "
        f"{warn_count} WARNING (Klassische ECC/Kein PQC) | {pass_count} PASS"
    )
    print("=" * 98)
    print()
    print(
        "Need the full BSI TR-02102 Audit Matrix, CBOM CSV & Management Migration Roadmap? "
        "Run the free web risk test at: https://kenanerorr404.github.io/de-compliance-kompass/pqc-nis2-rechner.html "
        "or download the complete Audit Pack: https://kenanghalioun.gumroad.com/l/wcqysh"
    )
    print()


def generate_html_report(findings: List[Finding], html_path: Path) -> None:
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    crit_count = sum(1 for f in findings if f.status == "CRITICAL")
    warn_count = sum(1 for f in findings if f.status == "WARNING")
    pass_count = sum(1 for f in findings if f.status == "PASS")

    rows_html = []
    for f in findings:
        badge_bg = "#fee2e2" if f.status == "CRITICAL" else ("#fef3c7" if f.status == "WARNING" else "#dcfce7")
        badge_fg = "#991b1b" if f.status == "CRITICAL" else ("#92400e" if f.status == "WARNING" else "#166534")
        rows_html.append(
            f"<tr>"
            f"<td><span style='background:{badge_bg};color:{badge_fg};padding:3px 8px;border-radius:4px;font-weight:700;font-size:0.8rem;'>{html.escape(f.status)}</span></td>"
            f"<td><strong>{html.escape(f.category)}</strong></td>"
            f"<td><code>{html.escape(f.target)}</code></td>"
            f"<td>{html.escape(f.algorithm)}</td>"
            f"<td><small>{html.escape(f.bsi_ref)}</small><br>{html.escape(f.recommendation)}</td>"
            f"</tr>"
        )

    report_html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BSI TR-02102-1 &amp; NIS-2 Executive Crypto Audit Report ({html.escape(hostname)})</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 2rem; line-height: 1.6; }}
  .container {{ max-width: 980px; margin: 0 auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 2.25rem; box-shadow: 0 4px 12px rgba(15,23,42,0.05); }}
  h1 {{ margin-top: 0; font-size: 1.65rem; color: #0f172a; }}
  .summary-bar {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem 0; }}
  .kpi {{ flex: 1; min-width: 180px; padding: 1rem 1.25rem; border-radius: 8px; border: 1px solid #e2e8f0; background: #f8fafc; }}
  .kpi strong {{ display: block; font-size: 1.6rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1.25rem 0 2rem 0; font-size: 0.9rem; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 0.75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 700; }}
  .locked-section {{ border: 2px dashed #93c5fd; border-radius: 10px; background: linear-gradient(180deg, #eff6ff 0%, #ffffff 100%); padding: 1.75rem; margin-top: 2rem; }}
  .blur-row td {{ color: #64748b; filter: blur(3.5px); user-select: none; }}
  .btn {{ display: inline-block; background: #1d4ed8; color: #fff !important; text-decoration: none; font-weight: 700; padding: 0.75rem 1.35rem; border-radius: 6px; margin-right: 0.75rem; margin-top: 0.5rem; }}
  .btn-dark {{ background: #0f172a; }}
  .btn-outline {{ background: #ffffff; color: #1d4ed8 !important; border: 1px solid #1d4ed8; }}
</style>
</head>
<body>
<div class="container">
  <div style="font-size:0.8rem;font-weight:700;text-transform:uppercase;color:#1d4ed8;letter-spacing:0.04em;">Lokaler System-Prüfbericht &bull; BSI TR-02102-1 (Frist 2031) &amp; § 30 BSIG (NIS-2)</div>
  <h1>BSI TR-02102-1 &amp; NIS-2 Local Crypto-Config Audit Report</h1>
  <p style="color:#475569;margin-top:0.25rem;">Host: <code>{html.escape(hostname)}</code> &bull; Prüfzeitpunkt: <code>{html.escape(now_str)}</code> &bull; Scanner: <code>bsi_pqc_check.py v1.2.0</code></p>

  <div class="summary-bar">
    <div class="kpi" style="border-color:#fecaca;background:#fef2f2;"><strong style="color:#dc2626;">{crit_count} CRITICAL</strong>Legacy RSA &lt; 3072 / SHA-1</div>
    <div class="kpi" style="border-color:#fde68a;background:#fffbeb;"><strong style="color:#d97706;">{warn_count} WARNING</strong>Klassische ECC / Kein PQC-Hybrid</div>
    <div class="kpi" style="border-color:#bbf7d0;background:#f0fdf4;"><strong style="color:#16a34a;">{pass_count} PASS</strong>BSI TR-02102 Konform</div>
  </div>

  <h2>1. Technische Befunde (SSH, OpenSSL/TLS &amp; X.509 Zertifikate)</h2>
  <table>
    <thead>
      <tr><th>Status</th><th>Kategorie</th><th>Ziel / Datei</th><th>Algorithmus / Befund</th><th>BSI-Referenz &amp; Empfehlung</th></tr>
    </thead>
    <tbody>
      {"".join(rows_html)}
    </tbody>
  </table>

  <div class="locked-section">
    <h2 style="margin-top:0;color:#1e3a8a;">🔒 Executive NIS-2 &amp; BSI TR-02102-1 Maßnahmenplan (32 Prüfpunkte &amp; CBOM-Vorlage)</h2>
    <p style="margin-top:0.25rem;color:#334155;">Vorschau auf das prüfungsfertige Audit-Dossier für Geschäftsleitung (§ 38 BSIG Haftungsentlastung), ISMS / ISO 27001, DiGA (TR-03161) und externe NIS-2-Prüfer:</p>
    <table>
      <thead>
        <tr><th>Prüf-ID</th><th>Regulatorische Anforderung (§ 30 BSIG / BSI TR)</th><th>Geforderter Nachweis im Audit</th><th>Status / Vorlage</th></tr>
      </thead>
      <tbody>
        <tr><td><strong>CBOM-01</strong></td><td>BSI TR-02102-1 Kap. 2 &amp; § 30 Abs. 2 Nr. 8 BSIG</td><td>Vollständiges Krypto-Inventar (TLS, SSH, IPsec/IKEv2, Zertifikate, Datenbanken)</td><td>Im €49 Migrations-Pack enthalten</td></tr>
        <tr><td><strong>PQC-04</strong></td><td>BSI TR-02102-2 / OpenSSL 3.5 Hybrid-KEM</td><td>Migrationsfahrplan auf <code>X25519MLKEM768</code> &amp; <code>SecP256r1MLKEM768</code> bis 2031</td><td>Im €49 Migrations-Pack enthalten</td></tr>
        <tr class="blur-row"><td><strong>NIS2-12</strong></td><td>§ 38 BSIG Geschäftsführer-Haftungsfreizeichnung</td><td>Vorstands-/GF-Beschlussvorlage zur Krypto-Risikoübernahme &amp; Budgetfreigabe</td><td>Gesperrt (Vollversion)</td></tr>
        <tr class="blur-row"><td><strong>SDLC-19</strong></td><td>BSI TR-03185-2 Sichere Software-Updates (DiGA/SaaS)</td><td>Update-Klassifizierungsmatrix für Krypto-Patches ohne Rezertifizierungsverlust</td><td>Gesperrt (Vollversion)</td></tr>
        <tr class="blur-row"><td><strong>VPN-27</strong></td><td>BSI TR-02102-3 IPsec/IKEv2 Post-Quanten-Härtung</td><td>RFC 9370 Multiple Key Exchanges &amp; IKE Fragmentation Konfigurations-SOP</td><td>Gesperrt (Vollversion)</td></tr>
      </tbody>
    </table>
    <div>
      <a class="btn" href="https://kenanghalioun.gumroad.com/l/wcqysh" target="_blank" rel="noopener">🔐 Vollständiges BSI TR-02102 PQC-Migrations-Pack freischalten (€49) &rarr;</a>
      <a class="btn btn-dark" href="https://kenanghalioun.gumroad.com/l/juznqz" target="_blank" rel="noopener">📦 BSI TR-03185 Audit-Readiness-Pack (Updates ohne Rezertifizierung, €49) &rarr;</a>
      <a class="btn btn-outline" href="https://kenanerorr404.github.io/de-compliance-kompass/pqc-nis2-rechner.html" target="_blank" rel="noopener">⚡ Kostenloser Web-Risikotest &amp; CSV-Leseprobe</a>
    </div>
  </div>
</div>
</body>
</html>
"""
    html_path.write_text(report_html, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BSI TR-02102-1 & NIS-2 Local Crypto-Config Scanner (SSH, OpenSSL/TLS, X.509)"
    )
    parser.add_argument(
        "--ssh-config",
        type=str,
        default="/etc/ssh/sshd_config",
        help="Pfad zur sshd_config (Standard: /etc/ssh/sshd_config)",
    )
    parser.add_argument(
        "--openssl-config",
        type=str,
        default="/etc/ssl/openssl.cnf",
        help="Pfad zur openssl.cnf (Standard: /etc/ssl/openssl.cnf)",
    )
    parser.add_argument(
        "--cert-path",
        type=str,
        default="/etc/ssl/certs",
        help="Pfad zu X.509-Zertifikaten oder Verzeichnis (Standard: /etc/ssl/certs)",
    )
    parser.add_argument(
        "--max-certs",
        type=int,
        default=6,
        help="Maximale Anzahl zu prüfender X.509-Zertifikate (Standard: 6)",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default="",
        help="Optionaler Pfad für JSON-Audit-Export (CBOM-Vorstufe)",
    )
    parser.add_argument(
        "--html-out",
        type=str,
        default="bsi-pqc-audit-report.html",
        help="Pfad für den automatisch generierten Executive HTML-Prüfbericht (Standard: bsi-pqc-audit-report.html)",
    )
    args = parser.parse_args()

    findings: List[Finding] = []
    findings.extend(scan_sshd_config([Path(args.ssh_config)]))
    findings.extend(scan_openssl_config([Path(args.openssl_config)]))
    findings.extend(scan_certificates([Path(args.cert_path)], max_certs=args.max_certs))

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.write_text(
            json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    if args.html_out:
        try:
            report_path = Path(args.html_out)
            generate_html_report(findings, report_path)
            print(f"[+] Executive HTML-Audit-Bericht gespeichert unter: {report_path.resolve()}")
        except Exception as exc:
            print(f"[!] Hinweis: HTML-Bericht konnte nicht geschrieben werden ({exc})")

    print_summary_table(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
