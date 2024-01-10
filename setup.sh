#!/usr/bin/env sh

set -eu

# URL_PREFIX=https://crashoverride.com/dl
URL_PREFIX=https://dl.crashoverride.run
SHA256=sha256sum
SUDO=sudo
TMP=/tmp

is_installed() {
    name=$1
    which "$name" > /dev/null 2>&1
}

# on osx, sha256sum doesnt exist and instead its shasum
if ! is_installed "$SHA256"; then
    SHA256="shasum -a 256"
fi

if ! is_installed sudo; then
    SUDO=
fi

# version of chalk to download
version=
# which config to load after install
load=
# json params to load
params=
# CrashOverride API token
token=
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
# instead of downloading chalk, copy it from this path
# this is meant for testing local chalk binaries
copy_from=
# chalk command timeout
timeout=60
# which platforms to download for multi-platform builds
platforms=

color() {
    (
        set +x
        name=$1
        shift
        color=
        end=
        if [ -z "${NO_COLOR:-}" ]; then
            case $name in
                yellow)
                    color="\033[0;33m"
                    ;;
                blue)
                    color="\033[0;34m"
                    ;;
                red)
                    color="\033[0;31m"
                    ;;
                green)
                    color="\033[0;32m"
                    ;;
            esac
            end="\033[0m"
        fi
        args="$*"
        printf "$color%s$end" "$args"
    )
}

info() {
    echo "$(color green INFO:)" "$@" > /dev/stderr
}

warn() {
    echo "$(color yellow WARN:)" "$@" > /dev/stderr
}

error() {
    echo "$(color red ERROR:)" "$@" > /dev/stderr
}

fatal() {
    error "$@"
    exit 1
}

first_owner() {
    path=$1
    while
        ! stat "$path" > /dev/null 2>&1
    do
        path=$(dirname "$path")
    done
    stat -c %u "$path"
}

am_owner() {
    path=$1
    uid=$(id -u)
    path_uid=$(first_owner "$path")
    [ "$uid" = "$path_uid" ]
}

enable_debug() {
    set -x
    log_level=trace
    debug=true
}

# wrapper for calling chalk within the script
chalk() {
    $SUDO chmod +xr "$chalk_path"
    timeout -s KILL "${timeout}s" $SUDO "$chalk_path" --log-level=$log_level --skip-summary-report --skip-command-report "$@"
}

# find out latest chalk version
get_latest_version() {
    info Querying latest version of chalk
    version=$(curl -fsSL "$URL_PREFIX/chalk/current-version.txt")
    info Latest version is "$version"
    echo "$version"
}

# get the folder what to download
chalk_folder() {
    if echo "$version" | grep -E '^[a-fA-F0-9]{40}$' > /dev/null 2>&1; then
        echo "chalk-commit-builds"
    else
        echo "chalk"
    fi
}

# get the chalk file name for the version/os/architecture
chalk_version_name() {
    os=${os:-$(uname -s)}
    arch=${arch:-$(uname -m)}
    echo "chalk-$version-$os-$arch"
}

# download chalk and validate its checksum
download_chalk() {
    name=$(chalk_version_name)
    chalk_tmp=$TMP/$(chalk_version_name)

    if [ -n "$copy_from" ]; then
        info Copying existing chalk from "$copy_from"
        cp "$copy_from" "$TMP/$name"
        return
    fi

    url=$URL_PREFIX/$(chalk_folder)/$name
    info Downloading chalk from "$url"
    rm -f "$TMP/$name" "$TMP/$name.sha256"
    wget --quiet --directory-prefix=$TMP "$url" "$url.sha256" || (
        fatal Could not download "$name". Are you sure this is a valid version?
    )
    if ! [ -f "$chalk_tmp" ]; then
        return 1
    fi
    checksum=$(cat "$chalk_tmp.sha256")
    info Validating sha256 checksum "${checksum%% *}"
    (
        cd $TMP
        $SHA256 -c "$chalk_tmp.sha256" > /dev/stderr || (
            error Expected checksum:
            cat "$chalk_tmp.sha256" > /dev/stderr
            error Downloaded checksum:
            $SHA256 "$chalk_tmp" > /dev/stderr
            fatal Oh no. Checksum validation failed. Exiting as chalk binary might of been tampered with
        )
    )
}

# validate downloaded chalk can run on the system
# and then install it to $chalk_path which should be on PATH
install_chalk() {
    info Checking chalk version
    chalk_path=$chalk_tmp chalk version
    info Installing chalk to "$chalk_path"
    $SUDO mkdir -p "$(dirname "$chalk_path")"
    $SUDO cp "$chalk_tmp" "$chalk_path"
    $SUDO chmod +xr "$chalk_tmp"
}

download_platform() {
    platform=$1
    case $platform in
        */*)
            os=$(echo "$platform" | cut -d/ -f1)
            arch=$(echo "$platform" | cut -d/ -f2)
            ;;
        *)
            os=$(uname -s | tr "[:upper:]" "[:lower:]")
            arch=$platform
            ;;
    esac
    download_chalk
    if ! [ -f "$chalk_tmp" ]; then
        return 1
    fi
    arch_path=~/.local/chalk/bin/${os}-${arch}/chalk
    info Copying chalk "$os/$arch" to "$arch_path"
    mkdir -p "$(dirname "$arch_path")"
    cp "$chalk_tmp" "$arch_path"
    chmod +xr "$arch_path"
}

normalize_cosign() {
    if is_installed cosign; then
        # TODO fix in src/configs/attestation.c4m
        info Copying cosign to /tmp for chalk
        cp "$(which cosign)" /tmp/cosign
    fi
}

# load custom chalk config
load_config() {
    module="${load%.*}"
    if [ -z "$params" ] && [ -n "$token" ]; then
        params="[[true, \"$module\", \"auth_config.crashoverride.token\", \"string\", \"$token\"]]"
    fi
    info PARAMS "$params"
    if [ -n "$params" ]; then
        echo "$params" | chalk load "$load" --params
    else
        chalk load "$load"
    fi
    if [ -n "$debug" ]; then
        chalk dump
        chalk dump cache
    fi
}

# add line to config file if its not there already
add_line_to_config() {
    line=$1
    config=$2
    if grep "$line" "$config" > /dev/null 2>&1; then
        info "$line" is already configured in chalk config
        return 0
    fi
    info Adding "'$line'" to chalk config
    echo >> "$config"
    echo "$line" >> "$config"
}

# add lines to chalk config
add_lines_to_chalk() {
    name=$1
    shift
    config=$(mktemp -t "chalk_${name}_XXXXXX").c4m
    touch "$config"
    for i; do
        echo "$i" >> "$config"
    done
    chalk load "$config"
    if [ -n "$debug" ]; then
        chalk dump
        chalk dump cache
    fi
}

# add necessary configs to wrap command with chalk
add_cmd_exe_to_config() {
    cmd=$1
    path=$2
    folder=$(dirname "$path")
    add_lines_to_chalk \
        "$cmd" \
        "default_command = \"$cmd\"" \
        "${cmd}_exe = \"$folder\""
}

# wrap given command with chalk
wrap_cmd() {
    cmd=$1

    if ! is_installed "$cmd"; then
        return
    fi

    existing_path=$(which "$cmd")
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
    $SUDO rm "$chalked_path" 2> /dev/null || true
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
        --token=*)
            token=${arg##*=}
            ;;
        --params=*)
            params=${arg##*=}
            info SETTING PARAMS
            ;;
        --prefix=*)
            prefix=${arg##*=}
            prefix=$(echo "$prefix" | sed "s#~#$HOME#" | sed 's/bin$//')
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
        --copy-from=*)
            copy_from=${arg##*=}
            ;;
        --timeout=*)
            timeout=${arg##*=}
            ;;
        --platforms=*)
            platforms=${arg##*=}
            ;;
        *)
            set -- "$@" "$arg"
            ;;
    esac
done

if [ "${ACTIONS_STEP_DEBUG:-}" = "true" ]; then
    enable_debug
fi

if ! echo "$PATH" | tr ":" "\n" | grep "$prefix/bin"; then
    fatal "$prefix/bin" is not part of PATH. "--prefix=<prefix>/bin" must be part of PATH
fi

chalk_path=$prefix/bin/chalk
chalk_tmp=

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

    download_chalk
    install_chalk
    normalize_cosign
else
    info "$chalk_path" is already installed. skipping
fi

for platform in $(echo "$platforms" | tr "," "\n"); do
    download_platform "$platform" || (
        warn Chalk will not be able to wrap builds for "$platform"
    )
done

if [ -n "$load" ]; then
    info Loading custom chalk config from "$load"
    load_config
fi

if [ -n "$debug" ]; then
    info Debug mode is enabled. Changing default chalk log level to trace
    params='' token='' load=https://chalkdust.io/debug.c4m load_config
fi

if [ -n "$wrap" ]; then
    wrap_cmd docker
fi
