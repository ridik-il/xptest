#!/bin/bash
# start-functions.sh — Start Crossplane function containers for xptest render.
#
# Usage:
#   ./scripts/start-functions.sh                        # Start all well-known functions
#   ./scripts/start-functions.sh --composition comp.yaml # Start only functions used in composition
#   ./scripts/start-functions.sh --stop                  # Stop and remove all function containers
#   ./scripts/start-functions.sh --status                # Show status of function containers
#
# The containers run on a shared Docker network (crossplane-net) with gRPC on port 9443.
# crossplane render connects to them via Development runtime annotations in functions.yaml.

set -euo pipefail

DOCKER_NETWORK="crossplane-net"
CONTAINER_PORT="9443"

# Well-known function images (same versions as crossplane-composition-tester reference)
declare -A FUNCTION_IMAGES=(
    ["function-go-templating"]="xpkg.upbound.io/crossplane-contrib/function-go-templating:v0.7.0"
    ["function-auto-ready"]="xpkg.upbound.io/crossplane-contrib/function-auto-ready:v0.3.0"
    ["function-environment-configs"]="xpkg.upbound.io/crossplane-contrib/function-environment-configs:v0.1.0"
    ["function-patch-and-transform"]="xpkg.upbound.io/crossplane-contrib/function-patch-and-transform:v0.8.0"
    ["function-kcl"]="xpkg.upbound.io/crossplane-contrib/function-kcl:v0.9.0"
)

# Default: start these three (most common pipeline)
DEFAULT_FUNCTIONS=(
    "function-go-templating"
    "function-environment-configs"
    "function-auto-ready"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }
log_info() { echo -e "  → $1"; }

# ── Preflight checks ──────────────────────────────────────────────────────────

check_docker() {
    if ! command -v docker &>/dev/null; then
        log_err "Docker is not installed or not on PATH."
        exit 1
    fi
    if ! docker info &>/dev/null; then
        log_err "Docker daemon is not running. Start Docker first."
        exit 1
    fi
    log_ok "Docker is running ($(docker info --format '{{.ServerVersion}}' 2>/dev/null))"
}

check_crossplane_cli() {
    if ! command -v crossplane &>/dev/null; then
        log_err "Crossplane CLI not found on PATH."
        log_info "Install: curl -sL https://raw.githubusercontent.com/crossplane/crossplane/master/install.sh | sh"
        exit 1
    fi
    local version
    version=$(crossplane version --client 2>/dev/null | grep -oP 'v[\d.]+' || echo "unknown")
    log_ok "Crossplane CLI found ($version)"
}

# ── Network management ────────────────────────────────────────────────────────

ensure_network() {
    if docker network inspect "$DOCKER_NETWORK" &>/dev/null; then
        log_ok "Docker network '$DOCKER_NETWORK' exists"
    else
        docker network create "$DOCKER_NETWORK" >/dev/null
        log_ok "Created Docker network '$DOCKER_NETWORK'"
    fi
}

# ── Container management ──────────────────────────────────────────────────────

container_running() {
    local name="$1"
    docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q "true"
}

container_exists() {
    local name="$1"
    docker inspect "$name" &>/dev/null
}

start_function() {
    local func_name="$1"
    local image="${FUNCTION_IMAGES[$func_name]:-}"

    if [ -z "$image" ]; then
        log_warn "Unknown function '$func_name' — no image mapping. Skipping."
        return 1
    fi

    if container_running "$func_name"; then
        log_ok "$func_name is already running"
        return 0
    fi

    # Remove stopped container if it exists
    if container_exists "$func_name"; then
        docker rm -f "$func_name" >/dev/null 2>&1
    fi

    log_info "Starting $func_name ($image) ..."
    if docker run \
        --network "$DOCKER_NETWORK" \
        -d \
        --name "$func_name" \
        "$image" \
        --insecure --address=":${CONTAINER_PORT}" >/dev/null 2>&1; then

        # Wait for container to be healthy (up to 10s)
        local waited=0
        while [ $waited -lt 10 ]; do
            if container_running "$func_name"; then
                log_ok "$func_name started successfully"
                return 0
            fi
            sleep 1
            waited=$((waited + 1))
        done
        log_err "$func_name failed to start. Check: docker logs $func_name"
        return 1
    else
        log_err "Failed to start $func_name. Try: docker pull $image"
        return 1
    fi
}

stop_all() {
    echo "Stopping all xptest function containers..."
    local stopped=0
    for func_name in "${!FUNCTION_IMAGES[@]}"; do
        if container_exists "$func_name"; then
            docker rm -f "$func_name" >/dev/null 2>&1
            log_ok "Stopped $func_name"
            stopped=$((stopped + 1))
        fi
    done
    if [ $stopped -eq 0 ]; then
        log_info "No function containers were running."
    fi

    # Remove network if no other containers use it
    if docker network inspect "$DOCKER_NETWORK" &>/dev/null; then
        local containers
        containers=$(docker network inspect "$DOCKER_NETWORK" --format '{{len .Containers}}' 2>/dev/null || echo "0")
        if [ "$containers" = "0" ]; then
            docker network rm "$DOCKER_NETWORK" >/dev/null 2>&1 || true
            log_ok "Removed Docker network '$DOCKER_NETWORK'"
        fi
    fi
}

show_status() {
    echo "Function container status:"
    echo "─────────────────────────────────────────────────────"
    printf "%-35s %-10s %s\n" "FUNCTION" "STATUS" "IMAGE"
    echo "─────────────────────────────────────────────────────"
    for func_name in "${!FUNCTION_IMAGES[@]}"; do
        local status image
        image="${FUNCTION_IMAGES[$func_name]}"
        if container_running "$func_name"; then
            status="${GREEN}running${NC}"
        elif container_exists "$func_name"; then
            status="${YELLOW}stopped${NC}"
        else
            status="${RED}absent${NC}"
        fi
        printf "%-35s $(echo -e $status)  %s\n" "$func_name" "$image"
    done
    echo ""

    # Network status
    if docker network inspect "$DOCKER_NETWORK" &>/dev/null; then
        log_ok "Network '$DOCKER_NETWORK' exists"
    else
        log_warn "Network '$DOCKER_NETWORK' does not exist"
    fi
}

# ── Extract functions from composition YAML ───────────────────────────────────

extract_functions_from_composition() {
    local comp_path="$1"
    # Extract unique functionRef names from the composition
    grep -oP 'functionRef:\s*\n\s+name:\s+\K[^\s]+' "$comp_path" 2>/dev/null \
        || grep -A1 'functionRef:' "$comp_path" | grep 'name:' | awk '{print $2}' | sort -u
}

# ── Main ──────────────────────────────────────────────────────────────────────

COMPOSITION=""
ACTION="start"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stop)
            ACTION="stop"
            shift
            ;;
        --status)
            ACTION="status"
            shift
            ;;
        --composition)
            COMPOSITION="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--composition <path>] [--stop] [--status]"
            echo ""
            echo "Options:"
            echo "  --composition <path>  Start only functions referenced in this composition"
            echo "  --stop                Stop all function containers and remove network"
            echo "  --status              Show status of function containers"
            echo "  -h, --help            Show this help"
            exit 0
            ;;
        *)
            log_err "Unknown argument: $1"
            exit 1
            ;;
    esac
done

case "$ACTION" in
    stop)
        stop_all
        exit 0
        ;;
    status)
        show_status
        exit 0
        ;;
esac

# Start functions
echo "═══════════════════════════════════════════════════════"
echo "  xptest — Starting Crossplane function containers"
echo "═══════════════════════════════════════════════════════"
echo ""

check_docker
check_crossplane_cli
ensure_network

echo ""

# Determine which functions to start
FUNCTIONS_TO_START=()
if [ -n "$COMPOSITION" ]; then
    if [ ! -f "$COMPOSITION" ]; then
        log_err "Composition file not found: $COMPOSITION"
        exit 1
    fi
    mapfile -t FUNCTIONS_TO_START < <(extract_functions_from_composition "$COMPOSITION")
    if [ ${#FUNCTIONS_TO_START[@]} -eq 0 ]; then
        log_warn "No functionRef found in composition, using defaults"
        FUNCTIONS_TO_START=("${DEFAULT_FUNCTIONS[@]}")
    else
        log_info "Functions from composition: ${FUNCTIONS_TO_START[*]}"
    fi
else
    FUNCTIONS_TO_START=("${DEFAULT_FUNCTIONS[@]}")
fi

echo ""
FAILED=0
for func in "${FUNCTIONS_TO_START[@]}"; do
    if ! start_function "$func"; then
        FAILED=$((FAILED + 1))
    fi
done

echo ""
if [ $FAILED -eq 0 ]; then
    log_ok "All function containers are running."
    echo ""
    echo "You can now run:"
    echo "  xptest validate --composition <path> --xrd <path> --render-mode render"
    echo ""
    echo "To stop containers later:"
    echo "  $0 --stop"
else
    log_err "$FAILED function(s) failed to start."
    exit 1
fi
