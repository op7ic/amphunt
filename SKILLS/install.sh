#\!/usr/bin/env bash
#
# install.sh - Deploy amphunt AI skills to their platform-native locations.
#
# Each AI platform expects files in specific locations at the repository root.
# This script creates symlinks (default) or copies the skill files from SKILLS/
# to the correct root-level locations for auto-discovery.
#
# Usage:
#   bash SKILLS/install.sh [claude|codex|gemini|all] [--copy]
#
# Options:
#   claude   Install Claude Code skills only (.claude/skills/)
#   codex    Install Codex CLI skills only (AGENTS.md + instructions/)
#   gemini   Install Gemini CLI skills only (GEMINI.md + playbooks/)
#   all      Install all platforms (default)
#   --copy   Copy files instead of creating symlinks
#
# Examples:
#   bash SKILLS/install.sh              # Symlink all platforms
#   bash SKILLS/install.sh claude       # Symlink Claude only
#   bash SKILLS/install.sh all --copy   # Copy all platforms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="symlink"
PLATFORMS=()

for arg in "$@"; do
  case "$arg" in
    --copy) MODE="copy" ;;
    claude|codex|gemini|all) PLATFORMS+=("$arg") ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# Default to all
if [ ${#PLATFORMS[@]} -eq 0 ]; then
  PLATFORMS=("all")
fi

deploy() {
  local src="$1"
  local dst="$2"

  if [ -e "$dst" ] || [ -L "$dst" ]; then
    echo "  [skip] $dst already exists"
    return
  fi

  if [ "$MODE" = "symlink" ]; then
    ln -s "$src" "$dst"
    echo "  [link] $dst -> $src"
  else
    if [ -d "$src" ]; then
      cp -r "$src" "$dst"
    else
      cp "$src" "$dst"
    fi
    echo "  [copy] $dst"
  fi
}

install_claude() {
  echo ""
  echo "=== Installing Claude Code skills ==="
  echo "  Target: .claude/skills/  (auto-discovered by Claude Code)"

  mkdir -p "$REPO_ROOT/.claude"
  deploy "SKILLS/.claude/skills" "$REPO_ROOT/.claude/skills"
}

install_codex() {
  echo ""
  echo "=== Installing Codex CLI skills ==="
  echo "  Target: AGENTS.md + instructions/  (auto-discovered by Codex CLI)"

  deploy "SKILLS/.codex/AGENTS.md" "$REPO_ROOT/AGENTS.md"
  deploy "SKILLS/.codex/instructions" "$REPO_ROOT/instructions"
}

install_gemini() {
  echo ""
  echo "=== Installing Gemini CLI skills ==="
  echo "  Target: GEMINI.md + playbooks/  (auto-discovered by Gemini CLI)"

  deploy "SKILLS/.gemini/GEMINI.md" "$REPO_ROOT/GEMINI.md"
  deploy "SKILLS/.gemini/playbooks" "$REPO_ROOT/playbooks"
}

echo "amphunt AI Skills Installer"
echo "Mode: $MODE"

for platform in "${PLATFORMS[@]}"; do
  case "$platform" in
    claude) install_claude ;;
    codex)  install_codex ;;
    gemini) install_gemini ;;
    all)
      install_claude
      install_codex
      install_gemini
      ;;
  esac
done

echo ""
echo "Done. Verify with: python3 SKILLS/validate_skills.py"
