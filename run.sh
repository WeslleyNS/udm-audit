#!/bin/bash
# =============================================================================
# udm-audit — One-liner runner para UDM Pro
#
# Uso:
#   curl -sSL https://raw.githubusercontent.com/WeslleyNS/udm-audit/main/run.sh | bash
#   curl -sSL https://raw.githubusercontent.com/WeslleyNS/udm-audit/main/run.sh | bash -s -- --check CHK-002
#   curl -sSL https://raw.githubusercontent.com/WeslleyNS/udm-audit/main/run.sh | bash -s -- --severity HIGH --output /tmp/report.json
# =============================================================================
set -euo pipefail

REPO="https://github.com/WeslleyNS/udm-audit/archive/refs/heads/main.tar.gz"
WORKDIR="/tmp/udm-audit-$$"
CLEANUP=true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

cleanup() {
    if [ "$CLEANUP" = true ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

# --- Pre-flight checks ---
info "udm-audit — UDM Pro Security Audit Tool"
info "Verificando pré-requisitos..."

# Python 3.9+
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    fail "Python não encontrado. Instale Python 3.9+ antes de continuar."
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)" 2>/dev/null)
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)" 2>/dev/null)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]); then
    fail "Python $PY_VERSION detectado. Requer Python 3.9+."
fi
ok "Python $PY_VERSION detectado"

# curl ou wget
if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    fail "curl ou wget não encontrado."
fi

# --- Download ---
info "Baixando udm-audit..."
mkdir -p "$WORKDIR"

if command -v curl &>/dev/null; then
    curl -sSL "$REPO" | tar xz -C "$WORKDIR" --strip-components=1
elif command -v wget &>/dev/null; then
    wget -qO- "$REPO" | tar xz -C "$WORKDIR" --strip-components=1
fi
ok "Download concluído em $WORKDIR"

cd "$WORKDIR"

# --- Dependências ---
info "Instalando dependências..."
$PYTHON -m pip install --quiet --break-system-packages -r requirements.txt 2>/dev/null \
    || $PYTHON -m pip install --quiet -r requirements.txt 2>/dev/null \
    || {
        info "pip install falhou — tentando sem pip (dependências podem já estar instaladas)..."
        $PYTHON -c "import paramiko, rich, click, yaml" 2>/dev/null \
            || fail "Dependências faltando e pip install falhou. Instale manualmente: pip install -r requirements.txt"
    }
ok "Dependências OK"

# --- Executa ---
info "Executando audit em modo local..."
echo ""
$PYTHON main.py audit --local "$@"
