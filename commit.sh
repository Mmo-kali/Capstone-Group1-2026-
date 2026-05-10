#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  git-profile.sh --pid PID --name "User Name" --email user@example.com [--scope local|global|system]
  git-profile.sh --pid PID [--scope local|global|system]
  git-profile.sh --list
  git-profile.sh --pid PID --show
  git-profile.sh --pid PID --forget

Options:
  --pid PID       Profile ID to save or apply. Use letters, numbers, dots, underscores, or hyphens.
  --name NAME     Git author name to save for this PID.
  --email EMAIL   Git author email to save for this PID.
  --scope SCOPE   Git config scope to change. Defaults to local.
  --list          List saved profiles.
  --show          Show one saved profile.
  --forget        Delete one saved profile.
  -h, --help      Show this help.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
store_dir="$config_home/git-profiles"
store_file="$store_dir/profiles.tsv"

pid=""
name=""
email=""
scope="local"
list=false
show=false
forget=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid)
      [[ $# -ge 2 ]] || die "--pid needs a value"
      pid="$2"
      shift 2
      ;;
    --name)
      [[ $# -ge 2 ]] || die "--name needs a value"
      name="$2"
      shift 2
      ;;
    --email)
      [[ $# -ge 2 ]] || die "--email needs a value"
      email="$2"
      shift 2
      ;;
    --scope)
      [[ $# -ge 2 ]] || die "--scope needs a value"
      scope="$2"
      shift 2
      ;;
    --list)
      list=true
      shift
      ;;
    --show)
      show=true
      shift
      ;;
    --forget)
      forget=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$scope" in
  local|global|system) ;;
  *) die "--scope must be local, global, or system" ;;
esac

if [[ -n "$pid" && ! "$pid" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "--pid may only contain letters, numbers, dots, underscores, and hyphens"
fi

if [[ -n "$email" && ! "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  die "--email does not look like a valid email address"
fi

mkdir -p "$store_dir"
touch "$store_file"
chmod 700 "$store_dir"
chmod 600 "$store_file"

find_profile() {
  local wanted_pid="$1"
  awk -F '\t' -v wanted_pid="$wanted_pid" '$1 == wanted_pid { print; found = 1; exit } END { exit found ? 0 : 1 }' "$store_file"
}

save_profile() {
  local save_pid="$1"
  local save_name="$2"
  local save_email="$3"
  local temp_file

  temp_file="$(mktemp)"
  awk -F '\t' -v save_pid="$save_pid" '$1 != save_pid { print }' "$store_file" > "$temp_file"
  printf '%s\t%s\t%s\n' "$save_pid" "$save_name" "$save_email" >> "$temp_file"
  mv "$temp_file" "$store_file"
  chmod 600 "$store_file"
}

delete_profile() {
  local delete_pid="$1"
  local temp_file

  temp_file="$(mktemp)"
  awk -F '\t' -v delete_pid="$delete_pid" '$1 != delete_pid { print }' "$store_file" > "$temp_file"
  mv "$temp_file" "$store_file"
  chmod 600 "$store_file"
}

if "$list"; then
  if [[ ! -s "$store_file" ]]; then
    printf 'No saved profiles yet.\n'
    exit 0
  fi

  awk -F '\t' '{ printf "%s\t%s <%s>\n", $1, $2, $3 }' "$store_file" | sort
  exit 0
fi

[[ -n "$pid" ]] || die "--pid is required unless you use --list"

if "$show"; then
  profile="$(find_profile "$pid")" || die "no saved profile found for PID '$pid'"
  IFS=$'\t' read -r saved_pid saved_name saved_email <<< "$profile"
  printf '%s\t%s <%s>\n' "$saved_pid" "$saved_name" "$saved_email"
  exit 0
fi

if "$forget"; then
  find_profile "$pid" >/dev/null || die "no saved profile found for PID '$pid'"
  delete_profile "$pid"
  printf "Forgot profile '%s'.\n" "$pid"
  exit 0
fi

if [[ -n "$name" || -n "$email" ]]; then
  [[ -n "$name" && -n "$email" ]] || die "provide both --name and --email when creating or updating a profile"
  save_profile "$pid" "$name" "$email"
else
  profile="$(find_profile "$pid")" || die "no saved profile found for PID '$pid'; provide --name and --email to create it"
  IFS=$'\t' read -r _ name email <<< "$profile"
fi

command -v git >/dev/null 2>&1 || die "git was not found on PATH"

git config --global --unset user.email
git config --global --unset user.name

git config "--$scope" user.name "$name"
git config "--$scope" user.email "$email"

printf 'Git %s identity is now:\n' "$scope"
printf '  user.name  = %s\n' "$name"
printf '  user.email = %s\n' "$email"
printf '  PID        = %s\n' "$pid"
