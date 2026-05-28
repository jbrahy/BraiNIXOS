#!/usr/bin/env bash
# bin/run-brainx.sh — Build and live-boot the current BraiNIX working tree
#
# Wraps docker/test.sh so you can watch the GRUB → bootloader → kernel chain
# stream to your terminal in real time. The container is one-shot (--rm);
# nothing persists between runs except the cargo build cache under target/.
#
# Usage:
#   bin/run-brainx.sh             # build image if missing, then live-boot
#   bin/run-brainx.sh --rebuild   # force rebuild of the dev container image
#   bin/run-brainx.sh --no-net    # skip QEMU NIC + pcap capture
#   bin/run-brainx.sh --shell     # drop into a bash shell in the container
#   bin/run-brainx.sh --help      # this message
#
# To quit QEMU while it's running:
#   Ctrl-A then X      (QEMU's -nographic monitor escape)
#   Ctrl-C             (kills the docker container)

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="brainix-dev:latest"
CONTAINER_PLATFORM="linux/amd64"
DOCKERFILE_PATH="${REPO_ROOT}/docker/Dockerfile.dev"

usage() {
    cat <<'USAGE'
bin/run-brainx.sh — Build and live-boot the current BraiNIX working tree

Wraps docker/test.sh so you can watch the GRUB → bootloader → kernel chain
stream to your terminal in real time. The container is one-shot (--rm);
nothing persists between runs except the cargo build cache under target/.

Usage:
  bin/run-brainx.sh             build image if missing, then live-boot
  bin/run-brainx.sh --rebuild   force rebuild of the dev container image
  bin/run-brainx.sh --no-net    skip QEMU NIC + pcap capture
  bin/run-brainx.sh --shell     drop into a bash shell in the container
  bin/run-brainx.sh --help      this message

To quit QEMU while it is running:
  Ctrl-A then X      QEMU -nographic monitor escape
  Ctrl-C             kills the docker container
USAGE
}

REBUILD=false
SHELL_MODE=false
NO_NET=false
for arg in "$@"; do
    case "$arg" in
        --rebuild)  REBUILD=true ;;
        --no-net)   NO_NET=true ;;
        --shell)    SHELL_MODE=true ;;
        --help|-h)  usage; exit 0 ;;
        *)          printf "${RED}unknown flag: %s${NC}\n" "$arg"; usage; exit 2 ;;
    esac
done

require_command() {
    local name="$1"
    if ! command -v "$name" >/dev/null 2>&1; then
        printf "${RED}error:${NC} %s not found on PATH\n" "$name" >&2
        exit 1
    fi
}

require_command docker

if ! docker info >/dev/null 2>&1; then
    printf "${RED}error:${NC} docker daemon is not running. Start Docker Desktop and retry.\n" >&2
    exit 1
fi

image_present() {
    docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1
}

build_image() {
    printf "${BOLD}Building %s from %s ...${NC}\n" "${IMAGE_NAME}" "${DOCKERFILE_PATH}"
    docker build \
        --platform "${CONTAINER_PLATFORM}" \
        -f "${DOCKERFILE_PATH}" \
        -t "${IMAGE_NAME}" \
        "${REPO_ROOT}"
}

if [[ "${REBUILD}" == true ]] || ! image_present; then
    build_image
else
    printf "${GREEN}Using cached image ${IMAGE_NAME}.${NC}  (--rebuild to refresh)\n"
fi

# Common docker-run arguments.
#
# IMPORTANT: do not pass `-it` for the boot path. With -it allocated, docker
# attaches a pseudo-TTY to the container's stdin; qemu in -nographic mode then
# behaves differently because `tee /tmp/boot.log` makes stdout a pipe while
# stdin is a TTY — qemu produces no serial output and exits, leaving an empty
# boot log and an immediate `FAIL: BraiNIX: boot complete not found`.
# Foreground docker without -it streams qemu's stdout cleanly to the terminal
# and Ctrl-C is still forwarded as SIGINT.
docker_run_args=(
    --rm
    --platform "${CONTAINER_PLATFORM}"
    --security-opt seccomp=unconfined
    -v "${REPO_ROOT}:/home/dev/brainix"
    -w /home/dev/brainix
    --user dev
    --entrypoint bash
)

if [[ "${SHELL_MODE}" == true ]]; then
    printf "${BOLD}Dropping into a shell in %s ...${NC}\n" "${IMAGE_NAME}"
    # --shell needs a real TTY; ensure stdin is a TTY before requesting one.
    if [[ -t 0 && -t 1 ]]; then
        docker run -it "${docker_run_args[@]}" "${IMAGE_NAME}" -l
    else
        printf "${RED}error:${NC} --shell needs an interactive terminal (stdin/stdout must be TTYs).\n" >&2
        exit 1
    fi
    exit $?
fi

printf "\n${BOLD}=== BraiNIX live boot ===${NC}\n"
printf "Branch/commit:   %s\n" "$(git -C "${REPO_ROOT}" describe --always --dirty 2>/dev/null || echo unknown)"
printf "Image:           %s\n" "${IMAGE_NAME}"
printf "Repo mounted at: /home/dev/brainix\n"
if [[ "${NO_NET}" == true ]]; then
    printf "Network:         ${YELLOW}disabled${NC} (--no-net)\n"
    docker_run_args+=( -e QEMU_NO_NET=1 )
else
    printf "Network:         user-mode NIC (e1000), pcap to /tmp/qemu-net.pcap inside container\n"
fi
printf "${YELLOW}While QEMU is running:${NC}  Ctrl-A X to quit, or Ctrl-C this terminal.\n\n"

# Stream docker/test.sh to the terminal. Disabling pipefail so a 124 (timeout)
# exit from the inner qemu doesn't kill our outer status reporting; the script
# already prints its own PASS/FAIL line.
set +e
docker run "${docker_run_args[@]}" "${IMAGE_NAME}" -c 'docker/test.sh'
status=$?
set -e

if [[ "${status}" -eq 0 ]]; then
    printf "\n${GREEN}${BOLD}docker/test.sh exited successfully.${NC}\n"
else
    printf "\n${RED}${BOLD}docker/test.sh exited with status %s.${NC}\n" "${status}"
fi
exit "${status}"
