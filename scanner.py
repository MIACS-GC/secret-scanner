#!/usr/bin/env python3
"""
scanner.py — Escáner de secretos para repositorios git
Detecta credenciales, API keys, contraseñas y otros secretos en el código fuente.
Los secretos marcados con '# IGNORE' o listados en .false-positives se omiten.
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path

# ─────────────────────────────────────────────
#  Colores para la terminal
# ─────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────
#  Patrones de detección
# ─────────────────────────────────────────────
SECRET_PATTERNS = [
    {
        "name": "Contraseña en código",
        "pattern": r'(?i)(password|passwd|pwd)\s*=\s*["\'](?!.*\{)[^"\']{4,}["\']',
        "severity": "HIGH",
    },
    {
        "name": "Clave de API genérica",
        "pattern": r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
        "severity": "HIGH",
    },
    {
        "name": "Token genérico",
        "pattern": r'(?i)(token|secret|secret_key)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
        "severity": "HIGH",
    },
    {
        "name": "AWS Access Key",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": "CRITICAL",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r'(?i)aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']',
        "severity": "CRITICAL",
    },
    {
        "name": "Clave privada (PEM)",
        "pattern": r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "severity": "CRITICAL",
    },
    {
        "name": "Token GitHub",
        "pattern": r'ghp_[A-Za-z0-9]{36}',
        "severity": "CRITICAL",
    },
    {
        "name": "Token GitLab",
        "pattern": r'glpat-[A-Za-z0-9\-_]{20}',
        "severity": "CRITICAL",
    },
    {
        "name": "Cadena de conexión a base de datos",
        "pattern": r'(?i)(mysql|postgresql|mongodb|jdbc)\://[^"\'\s]+:[^"\'\s]+@',
        "severity": "HIGH",
    },
    {
        "name": "URL con credenciales",
        "pattern": r'https?://[^"\'\s]+:[^"\'\s@]+@[^"\'\s]+',
        "severity": "MEDIUM",
    },
    {
        "name": "Credencial hardcoded (username)",
        "pattern": r'(?i)(username|user)\s*=\s*["\'][^"\']{2,}["\']',
        "severity": "LOW",
    },
]

# Extensiones de fichero a escanear
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".env", ".cfg", ".conf", ".config", ".ini", ".yaml",
    ".yml", ".json", ".xml", ".sh", ".bash", ".zsh",
    ".tf", ".tfvars", ".properties", ".toml",
}

# Directorios a ignorar siempre
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# Ficheros a ignorar siempre
IGNORE_FILES = {"scanner.py", "pre-commit", ".false-positives"}


# ─────────────────────────────────────────────
#  Gestión de falsos positivos
# ─────────────────────────────────────────────
FALSE_POSITIVES_FILE = ".false-positives"

def load_false_positives():
    """Carga la lista de falsos positivos desde el fichero JSON."""
    if not Path(FALSE_POSITIVES_FILE).exists():
        return []
    try:
        with open(FALSE_POSITIVES_FILE) as f:
            data = json.load(f)
        return data.get("false_positives", [])
    except (json.JSONDecodeError, KeyError):
        return []

def save_false_positives(fp_list):
    """Guarda la lista de falsos positivos en el fichero JSON."""
    with open(FALSE_POSITIVES_FILE, "w") as f:
        json.dump({"false_positives": fp_list}, f, indent=2, ensure_ascii=False)

def is_false_positive(finding, fp_list):
    """Comprueba si un hallazgo coincide con algún falso positivo guardado."""
    for fp in fp_list:
        if (fp.get("file") == finding["file"] and
                fp.get("line_number") == finding["line_number"] and
                fp.get("match") == finding["match"]):
            return True
    return False

def is_inline_ignored(line):
    """Devuelve True si la línea contiene una marca de ignorar (# IGNORE, # nosec, etc.)."""
    ignore_markers = ["# IGNORE", "# nosec", "# noqa", "# secret-ignore", "# scanner:ignore"]
    return any(marker.lower() in line.lower() for marker in ignore_markers)


# ─────────────────────────────────────────────
#  Lógica de escaneo
# ─────────────────────────────────────────────
def scan_file(filepath, fp_list):
    """Escanea un fichero y devuelve la lista de secretos encontrados."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, PermissionError) as e:
        print(f"{YELLOW}[WARN] No se puede leer {filepath}: {e}{RESET}")
        return findings

    for line_num, line in enumerate(lines, start=1):
        # Saltar líneas marcadas con IGNORE inline
        if is_inline_ignored(line):
            continue

        for rule in SECRET_PATTERNS:
            matches = re.findall(rule["pattern"], line)
            if not matches:
                continue

            # re.findall devuelve grupos si los hay; tomamos la línea completa como match
            finding = {
                "file": str(filepath),
                "line_number": line_num,
                "line": line.rstrip(),
                "rule": rule["name"],
                "severity": rule["severity"],
                "match": line.strip(),
            }

            # Comprobar si es falso positivo registrado
            if is_false_positive(finding, fp_list):
                continue

            findings.append(finding)

    return findings

def scan_directory(root_dir, fp_list):
    """Escanea recursivamente un directorio y devuelve todos los hallazgos."""
    all_findings = []
    root = Path(root_dir)

    for path in root.rglob("*"):
        # Saltar directorios ignorados
        if any(ignored in path.parts for ignored in IGNORE_DIRS):
            continue
        # Solo ficheros
        if not path.is_file():
            continue
        # Saltar ficheros ignorados por nombre
        if path.name in IGNORE_FILES:
            continue
        # Filtrar por extensión (incluir también ficheros sin extensión como .env)
        if path.suffix not in SCAN_EXTENSIONS and path.name not in {".env", ".envrc"}:
            continue

        findings = scan_file(path, fp_list)
        all_findings.extend(findings)

    return all_findings

def scan_staged_files(fp_list):
    """Escanea solo los ficheros en staging area de git (para el hook pre-commit)."""
    import subprocess
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    staged_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

    all_findings = []
    for filepath in staged_files:
        path = Path(filepath)
        if path.name in IGNORE_FILES:
            continue
        if path.suffix not in SCAN_EXTENSIONS and path.name not in {".env", ".envrc"}:
            continue
        if path.exists():
            findings = scan_file(path, fp_list)
            all_findings.extend(findings)

    return all_findings


# ─────────────────────────────────────────────
#  Presentación de resultados
# ─────────────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": f"{BOLD}{RED}",
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
}

def print_findings(findings):
    """Imprime los hallazgos en la terminal con formato."""
    if not findings:
        print(f"\n{GREEN}{BOLD}✔  No se encontraron secretos.{RESET}\n")
        return

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}{RED}  ⚠  Se encontraron {len(findings)} secreto(s) potencial(es){RESET}")
    print(f"{BOLD}{'─'*60}{RESET}\n")

    for i, f in enumerate(findings, start=1):
        color = SEVERITY_COLOR.get(f["severity"], YELLOW)
        print(f"  [{i}] {color}{BOLD}[{f['severity']}]{RESET}  {f['rule']}")
        print(f"      📄 Fichero : {f['file']}")
        print(f"      📍 Línea  : {f['line_number']}")
        print(f"      🔍 Código : {f['line']}")
        print()


# ─────────────────────────────────────────────
#  Comando: marcar falso positivo
# ─────────────────────────────────────────────
def mark_false_positive(findings):
    """Menú interactivo para marcar hallazgos como falsos positivos."""
    if not findings:
        print(f"{GREEN}No hay hallazgos que marcar.{RESET}")
        return

    fp_list = load_false_positives()
    print_findings(findings)
    print(f"{CYAN}Introduce el número del hallazgo que deseas marcar como falso positivo")
    print(f"(o 'q' para salir):{RESET}")

    while True:
        choice = input("\n  Número: ").strip()
        if choice.lower() == "q":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(findings)):
            print(f"{YELLOW}  Número no válido. Introduce un número entre 1 y {len(findings)}.{RESET}")
            continue

        idx = int(choice) - 1
        finding = findings[idx]

        # Evitar duplicados
        if is_false_positive(finding, fp_list):
            print(f"{YELLOW}  Este hallazgo ya estaba marcado como falso positivo.{RESET}")
        else:
            fp_list.append({
                "file": finding["file"],
                "line_number": finding["line_number"],
                "match": finding["match"],
                "rule": finding["rule"],
                "comment": "Marcado manualmente como falso positivo",
            })
            save_false_positives(fp_list)
            print(f"{GREEN}  ✔ Marcado como falso positivo: [{finding['severity']}] {finding['rule']} en {finding['file']}:{finding['line_number']}{RESET}")

        print(f"\n{CYAN}  ¿Deseas marcar otro? (número o 'q' para salir):{RESET}")


# ─────────────────────────────────────────────
#  Punto de entrada principal
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Escáner de secretos para repositorios git",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python scanner.py                      # Escanea todo el directorio actual
  python scanner.py --path src/          # Escanea una carpeta específica
  python scanner.py --staged             # Solo ficheros en staging (para git hooks)
  python scanner.py --mark-fp            # Escanea y permite marcar falsos positivos
  python scanner.py --list-fp            # Muestra los falsos positivos registrados
        """
    )
    parser.add_argument("--path",    default=".",  help="Directorio a escanear (por defecto: .)")
    parser.add_argument("--staged",  action="store_true", help="Escanear solo ficheros en staging de git")
    parser.add_argument("--mark-fp", action="store_true", help="Modo interactivo para marcar falsos positivos")
    parser.add_argument("--list-fp", action="store_true", help="Listar los falsos positivos registrados")
    args = parser.parse_args()

    # ── Listar falsos positivos ──
    if args.list_fp:
        fp_list = load_false_positives()
        if not fp_list:
            print(f"{GREEN}No hay falsos positivos registrados.{RESET}")
        else:
            print(f"\n{BOLD}Falsos positivos registrados ({len(fp_list)}):{RESET}\n")
            for i, fp in enumerate(fp_list, 1):
                print(f"  [{i}] {fp.get('rule','?')} — {fp.get('file','?')}:{fp.get('line_number','?')}")
        return

    fp_list = load_false_positives()

    # ── Escanear ──
    print(f"\n{BOLD}{CYAN}🔍 Escaneando secretos...{RESET}")

    if args.staged:
        findings = scan_staged_files(fp_list)
    else:
        findings = scan_directory(args.path, fp_list)

    # ── Resultados ──
    if args.mark_fp:
        mark_false_positive(findings)
    else:
        print_findings(findings)

    # Código de salida: 1 si hay secretos (útil para el hook)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
