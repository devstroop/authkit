#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/setup-worktree.sh

Link shared build caches into the current Git worktree.

The shared cache is derived from Git's common directory and defaults to
<parent-of-primary-checkout>/.cache/<repository-name>. Set AUTHKIT_CACHE_ROOT
to use a different location.

The script creates target/ and node_modules/ in the shared cache, then links
them into the current worktree. It refuses to overwrite an existing file, real
directory, or symlink that points somewhere else. It never deletes data.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

resolve_dir() {
  (cd -- "$1" >/dev/null 2>&1 && pwd -P)
}

case "${1:-}" in
  "")
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown argument: %s\n\n' "$1" >&2
    usage >&2
    exit 2
    ;;
esac

if [ "$#" -gt 1 ]; then
  printf 'error: this script does not accept multiple arguments\n\n' >&2
  usage >&2
  exit 2
fi

command -v git >/dev/null 2>&1 || die "git is required"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "run this script from inside a Git worktree"

worktree_root=$(git rev-parse --show-toplevel)
worktree_root=$(resolve_dir "$worktree_root") || die "cannot resolve the worktree root"

common_dir=$(git rev-parse --git-common-dir)
case "$common_dir" in
  /*)
    ;;
  *)
    common_dir="$PWD/$common_dir"
    ;;
esac
common_dir=$(resolve_dir "$common_dir") || die "cannot resolve Git's common directory"

if [ "$(basename -- "$common_dir")" = ".git" ]; then
  project_root=$(dirname -- "$common_dir")
  cache_parent=$(dirname -- "$project_root")
  project_name=$(basename -- "$project_root")
else
  cache_parent=$(dirname -- "$common_dir")
  project_name=$(basename -- "$common_dir")
  project_name=${project_name%.git}
fi

[ -n "$project_name" ] || die "cannot determine the repository name"

if [ -n "${AUTHKIT_CACHE_ROOT:-}" ]; then
  cache_root=$AUTHKIT_CACHE_ROOT
  case "$cache_root" in
    /*)
      ;;
    *)
      cache_root="$PWD/$cache_root"
      ;;
  esac
else
  cache_root="$cache_parent/.cache/$project_name"
fi

mkdir -p -- "$cache_root/target" "$cache_root/node_modules"
cache_root=$(resolve_dir "$cache_root") || die "cannot resolve the shared cache directory"

preflight_link() {
  local name=$1
  local link="$worktree_root/$name"
  local shared="$cache_root/$name"

  if [ -L "$link" ]; then
    local current
    if ! current=$(resolve_dir "$link"); then
      die "$link is a symlink that does not resolve to a directory; refusing to modify it. Remove it manually if that is intended."
    fi

    local expected
    expected=$(resolve_dir "$shared") || die "cannot resolve shared cache directory $shared"

    if [ "$current" != "$expected" ]; then
      die "$link points to $current instead of $expected; refusing to replace it. Remove it manually if that is intended."
    fi
  elif [ -e "$link" ]; then
    die "$link already exists and is not a symlink; refusing to overwrite it. Move or remove it manually, then rerun this script."
  fi
}

ensure_link() {
  local name=$1
  local link="$worktree_root/$name"
  local shared="$cache_root/$name"

  if [ -L "$link" ]; then
    printf '%s is already linked to %s\n' "$link" "$(readlink -- "$link")"
    return 0
  fi

  ln -s -- "$shared" "$link"
  printf 'linked %s -> %s\n' "$link" "$shared"
}

preflight_link target
preflight_link node_modules

printf 'worktree: %s\n' "$worktree_root"
printf 'shared cache: %s\n' "$cache_root"

ensure_link target
ensure_link node_modules

printf '\nDone. Shared caches are ready. Do not commit target or node_modules.\n'
printf 'Note: cargo clean and dependency installs affect every worktree using these caches.\n'
