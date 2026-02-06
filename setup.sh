#!/usr/bin/env bash
# setup.sh — bootstrap ASM: create venv, install Python deps, download security tools.
# Usage: ./setup.sh [--force] [--tools-only] [--help]
set -euo pipefail

# ─── Globals ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
LIB_DIR="$SCRIPT_DIR/lib"
VENV_DIR="$SCRIPT_DIR/.venv"
FORCE=false
TOOLS_ONLY=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ─── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
fail()  { printf "${RED}[✗]${NC} %s\n" "$*"; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Bootstrap the ASM project — create Python venv, install dependencies,
and download security tools into ./bin/.

Options:
  --force        Re-download tools even if already present
  --tools-only   Skip Python venv setup, only install tools
  --help         Show this help message
EOF
    exit 0
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)      FORCE=true; shift ;;
        --tools-only) TOOLS_ONLY=true; shift ;;
        --help|-h)    usage ;;
        *) fail "Unknown option: $1" ;;
    esac
done

# ─── Prereqs ──────────────────────────────────────────────────────────────────

command -v python3 >/dev/null 2>&1 || fail "python3 is required but not found"
command -v curl    >/dev/null 2>&1 || fail "curl is required but not found"

HAS_UNZIP=true
if ! command -v unzip >/dev/null 2>&1; then
    HAS_UNZIP=false
    warn "unzip not found — will use Python zipfile fallback"
fi

# ─── Architecture detection ──────────────────────────────────────────────────

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $ARCH_RAW" ;;
esac
info "Detected architecture: $ARCH_RAW → $ARCH"

# ─── Python venv ──────────────────────────────────────────────────────────────

setup_venv() {
    if [[ -f "$VENV_DIR/bin/python3" ]] && [[ "$FORCE" == false ]]; then
        info "Python venv already exists — skipping (use --force to recreate)"
    else
        info "Creating Python venv at $VENV_DIR ..."
        python3 -m venv "$VENV_DIR"
        info "Venv created"
    fi
    info "Installing Python dependencies ..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    info "Python dependencies installed"
}

# ─── Tool installer helpers ──────────────────────────────────────────────────

mkdir -p "$BIN_DIR"

# Fetch the latest release tag for a GitHub repo.
# Usage: latest_tag "projectdiscovery/subfinder"
latest_tag() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])"
}

# Extract a .zip archive — uses unzip if available, else Python zipfile.
extract_zip() {
    local zip_path="$1" dest_dir="$2"
    if [[ "$HAS_UNZIP" == true ]]; then
        unzip -o -q "$zip_path" -d "$dest_dir"
    else
        python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    zf.extractall(sys.argv[2])
" "$zip_path" "$dest_dir"
    fi
}

# Install a ProjectDiscovery tool (subfinder, httpx, nuclei).
# These ship as .zip files containing a single binary.
install_pd_tool() {
    local tool="$1" repo="$2"

    if [[ -x "$BIN_DIR/$tool" ]] && [[ "$FORCE" == false ]]; then
        info "$tool already installed — skipping"
        return
    fi

    info "Installing $tool ..."
    local tag
    tag="$(latest_tag "$repo")"
    local ver="${tag#v}"
    local url="https://github.com/${repo}/releases/download/${tag}/${tool}_${ver}_linux_${ARCH}.zip"

    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '$tmp'" RETURN

    info "  Downloading ${tool} ${ver} ..."
    curl -fsSL -o "$tmp/${tool}.zip" "$url"
    extract_zip "$tmp/${tool}.zip" "$tmp"
    install -m 755 "$tmp/$tool" "$BIN_DIR/$tool"
    info "  $tool ${ver} → $BIN_DIR/$tool"
}

# ─── Install ProjectDiscovery tools ──────────────────────────────────────────

install_subfinder() { install_pd_tool "subfinder" "projectdiscovery/subfinder"; }
install_httpx()     { install_pd_tool "httpx"     "projectdiscovery/httpx"; }
install_nuclei()    { install_pd_tool "nuclei"    "projectdiscovery/nuclei"; }

# ─── Install amass ───────────────────────────────────────────────────────────

install_amass() {
    if [[ -x "$BIN_DIR/amass" ]] && [[ "$FORCE" == false ]]; then
        info "amass already installed — skipping"
        return
    fi

    info "Installing amass ..."
    local tag
    tag="$(latest_tag "owasp-amass/amass")"
    local ver="${tag#v}"
    local url="https://github.com/owasp-amass/amass/releases/download/${tag}/amass_Linux_${ARCH}.zip"

    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '$tmp'" RETURN

    info "  Downloading amass ${ver} ..."
    curl -fsSL -o "$tmp/amass.zip" "$url"
    extract_zip "$tmp/amass.zip" "$tmp"

    # amass zip contains a directory; find the binary inside
    local bin_path
    bin_path="$(find "$tmp" -name amass -type f -perm -u+x 2>/dev/null | head -1)"
    if [[ -z "$bin_path" ]]; then
        # fallback: look for any file named amass
        bin_path="$(find "$tmp" -name amass -type f | head -1)"
    fi
    if [[ -z "$bin_path" ]]; then
        warn "Could not find amass binary in archive — skipping"
        return
    fi
    install -m 755 "$bin_path" "$BIN_DIR/amass"
    info "  amass ${ver} → $BIN_DIR/amass"
}

# ─── Install nmap (three-tier strategy) ──────────────────────────────────────

install_nmap() {
    if [[ -x "$BIN_DIR/nmap" ]] && [[ "$FORCE" == false ]]; then
        info "nmap already available — skipping"
        return
    fi

    # Tier 1: system nmap exists — symlink it
    local sys_nmap
    sys_nmap="$(command -v nmap 2>/dev/null || true)"
    if [[ -n "$sys_nmap" ]]; then
        info "System nmap found at $sys_nmap — symlinking into $BIN_DIR/"
        ln -sf "$sys_nmap" "$BIN_DIR/nmap"
        return
    fi

    # Tier 2: sudo available — install via apt
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        info "Installing nmap via apt-get ..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq nmap
        sys_nmap="$(command -v nmap)"
        ln -sf "$sys_nmap" "$BIN_DIR/nmap"
        info "  nmap installed and symlinked"
        return
    fi

    # Tier 3: no sudo — extract .deb packages locally
    warn "No system nmap and no sudo — attempting local .deb extraction"
    local nmap_lib="$LIB_DIR/nmap"
    mkdir -p "$nmap_lib"

    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '$tmp'" RETURN

    local debs=("nmap" "nmap-common" "libpcap0.8t64" "liblua5.4-0" "liblinear4" "libblas3")
    info "  Downloading .deb packages ..."
    (cd "$tmp" && apt-get download "${debs[@]}" 2>/dev/null) || {
        # Retry with older package names
        debs=("nmap" "nmap-common" "libpcap0.8" "liblua5.3-0" "liblinear4" "libblas3")
        (cd "$tmp" && apt-get download "${debs[@]}" 2>/dev/null) || {
            warn "  Failed to download nmap .deb packages — skipping nmap"
            return
        }
    }

    info "  Extracting .deb packages ..."
    for deb in "$tmp"/*.deb; do
        dpkg-deb -x "$deb" "$nmap_lib"
    done

    # Detect the lib arch directory (e.g., x86_64-linux-gnu or aarch64-linux-gnu)
    local lib_arch_dir
    lib_arch_dir="$(find "$nmap_lib/usr/lib" -mindepth 1 -maxdepth 1 -type d -name '*-linux-*' 2>/dev/null | head -1)"

    # Build LD_LIBRARY_PATH from extracted libs
    local ld_paths="$nmap_lib/usr/lib"
    [[ -n "$lib_arch_dir" ]] && ld_paths="$lib_arch_dir:$ld_paths"
    [[ -d "$nmap_lib/lib" ]] && ld_paths="$nmap_lib/lib:$ld_paths"

    # Find the nmap binary inside extracted tree
    local nmap_bin
    nmap_bin="$(find "$nmap_lib" -name nmap -type f -path '*/bin/*' | head -1)"
    if [[ -z "$nmap_bin" ]]; then
        warn "  Could not find nmap binary in extracted debs — skipping"
        return
    fi

    # Create wrapper script that sets library paths
    cat > "$BIN_DIR/nmap" <<WRAPPER
#!/usr/bin/env bash
export LD_LIBRARY_PATH="${ld_paths}\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export NMAPDIR="$nmap_lib/usr/share/nmap"
exec "$nmap_bin" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/nmap"
    info "  nmap extracted locally with wrapper at $BIN_DIR/nmap"
}

# ─── Run installation ────────────────────────────────────────────────────────

if [[ "$TOOLS_ONLY" == false ]]; then
    setup_venv
fi

echo ""
info "Installing security tools into $BIN_DIR/ ..."
echo ""

install_subfinder
install_httpx
install_nuclei
install_amass
install_nmap

# ─── Verify ──────────────────────────────────────────────────────────────────

echo ""
info "Verification:"

TOOLS=("subfinder" "httpx" "nuclei" "amass" "nmap")
ALL_OK=true
for tool in "${TOOLS[@]}"; do
    if [[ -x "$BIN_DIR/$tool" ]]; then
        printf "  ${GREEN}✓${NC} %-12s %s\n" "$tool" "$BIN_DIR/$tool"
    else
        printf "  ${RED}✗${NC} %-12s not found\n" "$tool"
        ALL_OK=false
    fi
done

if [[ "$TOOLS_ONLY" == false ]]; then
    echo ""
    info "Checking Python imports ..."
    "$VENV_DIR/bin/python3" -c "import yaml, openpyxl; print('  yaml + openpyxl OK')"
    "$VENV_DIR/bin/python3" -c "
try:
    import boto3; print('  boto3 OK')
except ImportError:
    print('  boto3 not available (optional)')
"
fi

echo ""
if [[ "$ALL_OK" == true ]]; then
    info "Setup complete! Run: ./asm.sh --self-test"
else
    warn "Some tools failed to install. ASM will skip unavailable modules."
    warn "Run: ./asm.sh --self-test"
fi
