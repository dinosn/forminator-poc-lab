#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=forminator-poc-lab
PORT=${FORMINATOR_LAB_PORT:-8088}
BASE_URL="http://127.0.0.1:${PORT}"

case "$BASE_URL" in
  http://127.0.0.1:*) ;;
  *) printf '[test] refusing non-loopback URL: %s\n' "$BASE_URL" >&2; exit 1 ;;
esac

dc() {
  docker compose --project-directory "$ROOT" -p "$PROJECT" "$@"
}

wp() {
  dc exec -T -u www-data wordpress wp --path=/var/www/html "$@"
}

db_query() {
  dc exec -T db mariadb --batch --skip-column-names \
    -uwordpress -pwordpress-lab-only wordpress -e "$1" 2>/dev/null | tr -d '\r'
}

json_value() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

cleanup_posts() {
  local ids=${1:-}
  local -a post_ids
  if [[ -n "$ids" ]]; then
    read -r -a post_ids <<< "$ids"
    wp post delete "${post_ids[@]}" --force >/dev/null 2>&1 || true
  fi
}

assert_forminator_version() {
  local expected=${1:-1.56.1}
  local actual
  actual=$(wp plugin get forminator --field=version)
  [[ "$actual" == "$expected" ]] || {
    printf '[test] expected Forminator %s, got %s\n' "$expected" "$actual" >&2
    exit 1
  }
}
