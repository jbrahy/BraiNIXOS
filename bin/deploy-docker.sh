#!/usr/bin/env bash
# Build the BraiNIX dev container and start it with SSH on port 2222.
#
# Usage:
#   bin/deploy-docker.sh              — build image and start container
#   bin/deploy-docker.sh --rebuild    — force rebuild of the Docker image
#   bin/deploy-docker.sh --stop       — stop and remove the running container
#   bin/deploy-docker.sh --logs       — tail container logs
#
# Remote access:
#   SSH:    ssh -i ~/.ssh/brainix_dev -p 2222 dev@localhost
#   Serial: nc localhost 4444   (only active once Phase 1 kernel binary exists)

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CONTAINER_NAME="brainix-dev"
IMAGE_NAME="brainix-dev:latest"
SSH_PORT=2222
SERIAL_PORT=4444
SSH_KEY="$HOME/.ssh/brainix_dev"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Parse arguments
REBUILD=false
STOP=false
LOGS=false
for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=true ;;
        --stop)    STOP=true ;;
        --logs)    LOGS=true ;;
    esac
done

# Stop subcommand
if [[ "$STOP" == true ]]; then
    echo "Stopping ${CONTAINER_NAME}..."
    docker stop "$CONTAINER_NAME" 2>/dev/null && docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo "Done."
    exit 0
fi

# Logs subcommand
if [[ "$LOGS" == true ]]; then
    docker logs -f "$CONTAINER_NAME"
    exit 0
fi

# Require Docker
if ! command -v docker &>/dev/null; then
    echo "Docker is not installed. Install Docker Desktop: https://docs.docker.com/get-docker/"
    exit 1
fi

# Generate SSH keypair for passwordless access if it doesn't exist
if [[ ! -f "$SSH_KEY" ]]; then
    echo "Generating SSH keypair at ${SSH_KEY}..."
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "brainix-dev"
fi

# Build the Docker image
if [[ "$REBUILD" == true ]] || ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    printf "${BOLD}Building Docker image...${NC}\n"
    docker build \
        -f "${REPO_ROOT}/docker/Dockerfile.dev" \
        -t "$IMAGE_NAME" \
        "$REPO_ROOT"
fi

# Remove any existing container
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

printf "${BOLD}Starting container...${NC}\n"
docker run -d \
    --name "$CONTAINER_NAME" \
    --hostname brainix-dev \
    -p "${SSH_PORT}:22" \
    -p "${SERIAL_PORT}:4444" \
    -v "${REPO_ROOT}:/home/dev/brainix" \
    -v "${SSH_KEY}.pub:/home/dev/.ssh/authorized_keys:ro" \
    "$IMAGE_NAME"

# Wait for SSH to be ready (max 30s)
printf "Waiting for SSH..."
for attempt in $(seq 1 30); do
    if ssh -i "$SSH_KEY" \
            -p "$SSH_PORT" \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=1 \
            -o BatchMode=yes \
            "dev@localhost" true 2>/dev/null; then
        break
    fi
    printf "."
    sleep 1
    if [[ $attempt -eq 30 ]]; then
        printf "\nSSH not ready after 30s. Check: docker logs %s\n" "$CONTAINER_NAME"
        exit 1
    fi
done
printf " ${GREEN}ready${NC}\n\n"

printf "${GREEN}${BOLD}Container running.${NC}\n\n"
printf "  ${BOLD}SSH (dev shell):${NC}\n"
printf "    ssh -i %s -p %d dev@localhost\n\n" "$SSH_KEY" "$SSH_PORT"
printf "  ${BOLD}Serial console (Phase 1+, when kernel binary exists):${NC}\n"
printf "    nc localhost %d\n\n" "$SERIAL_PORT"
printf "  ${BOLD}Stop:${NC}\n"
printf "    bin/deploy-docker.sh --stop\n\n"
printf "  ${YELLOW}Note:${NC} QEMU only starts when a kernel binary exists at\n"
printf "         target/x86_64-unknown-none/release/brainix-kernel.\n"
printf "         Build one with: cargo build --release --target x86_64-unknown-none -p brainix-kernel\n"
