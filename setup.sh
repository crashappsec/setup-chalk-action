#!/usr/bin/env bash

set -eEu
set -o pipefail
shopt -s extglob

URL_PREFIX=https://crashoverride.com/dl
SHA256=sha256sum
SUDO=sudo
TMP=/tmp

# on osx, sha256sum doesnt exist and instead its shasum
if [ -z "$(which $SHA256 2> /dev/null)" ]; then
    SHA256="shasum -a 256"
fi

if [ -z "$(which sudo 2> /dev/null)" ]; then
    SUDO=
fi

# version of chalk to download
version=
# which config to load after install
load=
# ${prefix}/bin is where script should install chalk and wrapped commands
prefix=/usr/local
# whether to overwrite existing chalk binary
overwrite=true
# whether to wrap external commands with chalk
wrap=true
# chalk commands log level
log_level=error
# if running in debug mode
debug=

function color {
    (
        set +x
        declare -A COLORS
        if [ -z "${NO_COLOR:-}" ]; then
            COLORS[yellow]="\033[0;33m"
            COLORS[blue]="\033[0;34m"
            COLORS[red]="\033[0;31m"
            COLORS[green]="\033[0;32m"
            COLORS[end]="\033[0m"
        fi
        color=$(echo "$1" | tr "[:upper:]" "[:lower:]")
        shift
        args="$*"
        echo -en "${COLORS[$color]:-}$args${COLORS[end]:-}"
    )
}

function info {
    echo "$(color GREEN INFO:)" "$@" > /dev/stderr
}

function warn {
    echo "$(color yellow WARN:)" "$@" > /dev/stderr
}

function error {
    echo "$(color red ERROR:)" "$@" > /dev/stderr
}

function fatal {
    error "$@"
    exit 1
}

function first_owner {
    path=$1
    while ! stat "$path" &> /dev/null; do
        path=$(dirname "$path")
    done
    stat -c %u "$path"
}

function am_owner {
    path=$1
    uid=$(id -u)
    path_uid=$(first_owner "$path")
    [ "$uid" = "$path_uid" ]
}

function enable_debug {
    set -x
    log_level=trace
    debug=true
}

# wrapper for calling chalk within the script
function chalk {
    $SUDO chmod +xr "$chalk_path"
    timeout -s KILL 10s $SUDO "$chalk_path" --log-level=$log_level --skip-summary-report --skip-command-report "$@"
}

# find out latest chalk version
function get_latest_version {
    info Querying latest version of chalk
    version=$(curl -fsSL "$URL_PREFIX/current-version.txt")
    info Latest version is "$version"
    echo "$version"
}

# get the folder what to download
function chalk_folder {
    if echo "$version" | grep -E '^[a-fA-F0-9]{40}$' &> /dev/null; then
        echo "chalk-commit-builds"
    else
        echo "chalk"
    fi
}

# get the chalk file name for the version/os/architecture
function chalk_version_name {
    echo "chalk-$version-$(uname -s)-$(uname -m)"
}

# download chalk and validate its checksum
function download_chalk {
    name=$(chalk_version_name)
    url=$URL_PREFIX/$(chalk_folder)/$(chalk_version_name)
    info Downloading chalk from "$url"
    rm -f "$TMP/$name"{,.sha256}
    wget --quiet --directory-prefix=$TMP "$url"{,.sha256} || (
        fatal Could not download "$(chalk_version_name)". Are you sure this is a valid version?
    )
    checksum=$(cat "$chalk_tmp.sha256")
    info Validating sha256 checksum "${checksum%% *}"
    (
        cd $TMP
        $SHA256 -c "$chalk_tmp.sha256" || (
            error Expected checksum:
            cat "$chalk_tmp.sha256"
            error Downloaded checksum:
            $SHA256 "$chalk_tmp"
            fatal Oh no. Checksum validation failed. Exiting as chalk binary might of been tampered with
        )
    )
}

# validate downloaded chalk can run on the system
# and then install it to $chalk_path which should be on PATH
function install_chalk {
    info Checking chalk version
    chalk_path=$chalk_tmp chalk version
    info Installing chalk to "$chalk_path"
    $SUDO mkdir -p "$(dirname "$chalk_path")"
    $SUDO cp "$chalk_tmp" "$chalk_path"
}

function normalize_cosign {
    if which cosign 2> /dev/null; then
        # TODO fix in src/configs/attestation.c4m
        info Copying cosign to /tmp for chalk
        cp "$(which cosign)" /tmp/cosign
    fi
}

# load custom chalk config
function load_config {
    info Loading custom chalk config from "$load"
    chalk load --replace "$load"
}

# add line to config file if its not there already
function add_line_to_config {
    line=$1
    config=$2
    if grep "$line" "$config" &> /dev/null; then
        info "$cmd" path is already configured in chalk config
        return 0
    fi
    info Adding "'$line'" to chalk config
    echo >> "$config"
    echo "$line" >> "$config"
}

# add lines to chalk config
function add_lines_to_chalk {
    config=$(mktemp -t chalk_XXXXXX).c4m
    chalk dump > "$config"
    for i; do
        add_line_to_config "$i" "$config"
    done
    chalk load --replace "$config"
    if [ -n "$debug" ]; then
        chalk dump
    fi
}

# add necessary configs to wrap command with chalk
function add_cmd_exe_to_config {
    cmd=$1
    path=$2
    folder=$(dirname "$path")
    add_lines_to_chalk \
        "default_command = \"$cmd\"" \
        "${cmd}_exe = \"$folder\""
}

# wrap given command with chalk
function wrap_cmd {
    cmd=$1
    existing_path=$(which "$cmd" 2> /dev/null || true)
    chalked_path="$prefix/bin/$cmd"
    chalkless_path="$prefix/chalkless/$cmd"

    if [ -z "$existing_path" ]; then
        warn Skipping wrapping "$cmd" as it is not installed
        return 0
    fi

    info Wrapping "$existing_path" command with chalk

    $SUDO mkdir -p "$(dirname "$chalkless_path")"
    if am_owner "$existing_path"; then
        # hardlinking requires more permissions
        # so only doing when owning file
        info Hardlinking "$chalkless_path" to "$existing_path"
        $SUDO ln "$existing_path" "$chalkless_path"
    else
        info Copying "$chalkless_path" to "$existing_path"
        $SUDO cp "$existing_path" "$chalkless_path"
    fi

    # create temporary chalk copy so that we can adjust its configuration
    # to be able to find the moved binary in the chalkless location
    info Wrapping "$chalked_path" with chalk
    tmp=$(mktemp -t chalk.XXXXXX)
    $SUDO cp "$chalk_path" "$tmp"
    chalk_path=$tmp add_cmd_exe_to_config "$cmd" "$chalkless_path"
    $SUDO cp "$tmp" "$chalked_path"
    info Using "$chalked_path" will automatically use chalk now
}

for arg; do
    shift
    case "$arg" in
        --version=*)
            version=${arg##*=}
            ;;
        --load=*)
            load=${arg##*=}
            ;;
        --prefix=*)
            prefix=${arg##*=}
            prefix="${prefix/#\~/$HOME}"
            prefix=$(realpath "$prefix")
            ;;
        --chalk-path=*)
            chalk_path=${arg##*=}
            ;;
        --no-wrap)
            wrap=
            ;;
        --debug)
            enable_debug
            ;;
        --overwrite)
            overwrite=true
            ;;
        --no-overwrite)
            overwrite=
            ;;
        *)
            set -- "$@" "$arg"
            ;;
    esac
done

if [ "${ACTIONS_STEP_DEBUG:-}" = "true" ]; then
    enable_debug
fi

if [[ "$prefix" == *"/bin" ]]; then
    prefix=$(dirname "$prefix")
fi

if [[ "$PATH" != ?(*:)"$prefix/bin"?(:*) ]]; then
    fatal "$prefix/bin" is not part of PATH. "--prefix=<prefix>/bin" must be part of PATH
fi

chalk_path=$prefix/bin/chalk

if am_owner "$prefix"; then
    SUDO=
else
    if [ -z "$SUDO" ]; then
        fatal sudo is required to install chalk in "$prefix" as current user "'$(id -un)'" does not own it
    fi
fi

if ! [ -f "$chalk_path" ] || [ -n "$overwrite" ]; then
    if [ -f "$chalk_path" ]; then
        info "$chalk_path" is already installed. overwriting
    fi

    if [ -z "$version" ]; then
        version=$(get_latest_version)
    fi

    chalk_tmp=$TMP/$(chalk_version_name)

    download_chalk
    install_chalk
    normalize_cosign
else
    info "$chalk_path" is already installed. skipping
fi

if [ -n "$load" ]; then
    load_config
fi

if [ -n "$debug" ]; then
    info Debug mode is enabled. Changing default chalk log level to trace
    add_lines_to_chalk 'log_level: "trace"'
fi

if [ -n "$wrap" ]; then
    wrap_cmd docker
fi
