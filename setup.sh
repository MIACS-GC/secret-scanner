#!/bin/bash
# ─────────────────────────────────────────────────────────────
# setup.sh — Inicializa el repositorio y configura el hook
# Uso: bash setup.sh
# ─────────────────────────────────────────────────────────────

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Configuración del Escáner de Secretos   ${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
echo ""

# 1. Inicializar repositorio git si no existe
if [ ! -d ".git" ]; then
    echo -e "${CYAN}[1/3] Inicializando repositorio git...${RESET}"
    git init
    git add .
    git commit -m "feat: primer commit — estructura del proyecto" || true
    echo -e "${GREEN}  ✔ Repositorio git creado.${RESET}"
else
    echo -e "${YELLOW}[1/3] Ya existe un repositorio git. Se omite la inicialización.${RESET}"
fi

# 2. Instalar el hook pre-commit
echo ""
echo -e "${CYAN}[2/3] Instalando hook pre-commit...${RESET}"
cp .git-hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo -e "${GREEN}  ✔ Hook instalado en .git/hooks/pre-commit${RESET}"

# 3. Verificar Python 3
echo ""
echo -e "${CYAN}[3/3] Comprobando requisitos...${RESET}"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version)
    echo -e "${GREEN}  ✔ $PY_VERSION disponible.${RESET}"
else
    echo -e "${YELLOW}  ⚠ Python 3 no encontrado. Instálalo para usar el escáner.${RESET}"
fi

echo ""
echo -e "${BOLD}${GREEN}══ Instalación completada ══${RESET}"
echo ""
echo -e "  ${BOLD}Comandos disponibles:${RESET}"
echo -e "  ${CYAN}python3 scanner.py${RESET}              → Escanea todo el proyecto"
echo -e "  ${CYAN}python3 scanner.py --path src/${RESET}  → Escanea una carpeta"
echo -e "  ${CYAN}python3 scanner.py --mark-fp${RESET}    → Marcar falsos positivos"
echo -e "  ${CYAN}python3 scanner.py --list-fp${RESET}    → Ver falsos positivos"
echo -e "  ${CYAN}python3 scanner.py --staged${RESET}     → Solo ficheros en staging"
echo ""
echo -e "  ${BOLD}El hook pre-commit se activa automáticamente al hacer 'git commit'.${RESET}"
echo ""
