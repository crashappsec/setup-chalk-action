#!/usr/bin/env sh

set -eu

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

is_installed() {
    name=$1
    which "$name" > /dev/null 2>&1
}

# version of chalk to download
version=${CHALK_VERSION:-latest}
# which config to load after install
load=${CHALK_LOAD:-}
# json params to load
params=${CHALK_PARAMS:-}
# whether to automatically determine token via openid connect
connect=${CHALK_CONNECT:-}
# name of the custom profile to load
profile=${CHALK_PROFILE:-default}
# CrashOverride API token
token=${CHALK_TOKEN:-}
# OIDC token used to retrieve chalk token
oidc=${CHALK_OIDC:-}
# ${prefix}/bin is where script should install chalk and wrapped commands
prefix=${CHALK_PREFIX:-/usr/local}
# whether to overwrite existing chalk binary
overwrite=${CHALK_OVERWRITE:-true}
# whether to wrap external commands with chalk
wrap=${CHALK_WRAP:-true}
# chalk commands log level
log_level=${CHALK_LOG_LEVEL:-error}
# if running in debug mode
debug=${CHALK_DEBUG:-}
# instead of downloading chalk, copy it from this path
# this is meant for testing local chalk binaries
copy_from=${CHALK_COPY_FROM:-}
# chalk command timeout
timeout=${CHALK_TIMEOUT:-60}
# which platforms to download for multi-platform builds
platforms=${CHALK_PLATFORMS:-}
# information for signing
password=${CHALK_PASSWORD:-}
public_key=${CHALK_PUBLIC_KEY:-}
private_key=${CHALK_PRIVATE_KEY:-}
# run chalk setup
setup=${CHALK_SETUP:-}

URL_PREFIX=https://dl.crashoverride.run
SHA256=sha256sum
SUDO=sudo
TMP=/tmp

# on osx, sha256sum doesnt exist and instead its shasum
if ! is_installed "$SHA256"; then
    SHA256="shasum -a 256"
fi

if ! is_installed sudo; then
    SUDO=
fi

PROFILE=https://chalk.crashoverride.run/v0.1/profile
GITHUB_OPENID_CONNECT=https://chalk.crashoverride.run/v0.1/openid-connect/github
GITLAB_OPENID_CONNECT=https://chalk.crashoverride.run/v0.1/openid-connect/gitlab
if [ -n "${__CHALK_TESTING__:-}" ]; then
    warn Beware - chalk is now using test environment which is meant for internal chalk testing only.
    PROFILE=https://chalk-test.crashoverride.run/v0.1/profile
    GITHUB_OPENID_CONNECT=https://chalk-test.crashoverride.run/v0.1/openid-connect/github
    GITLAB_OPENID_CONNECT=https://chalk-test.crashoverride.run/v0.1/openid-connect/gitlab
fi

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

header_value() {
    file=$1
    name=$2
    grep -i "$name" < "$file" | awk '{print $2}' | tr -d '\r\n' \
        || (
            fatal Could not find header "$name" from response
        )
}

enable_debug() {
    set -x
    log_level=trace
    debug=true
}

openid_connect_github() {
    info Authenticating to CrashOverride via GitHub OpenID Connect
    github_jwt=$(mktemp -t github_jwt.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --header "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://crashoverride.run" \
        > "$github_jwt" \
        || (
            error Cannot generate GitHub OpenId Connect JWT Token.
            error Please make sure workflow/job has "'id-token: write'" permission.
            fatal See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings
        )
    co_headers=$(mktemp -t co_jwt.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --data-binary @"$github_jwt" \
        --dump-header "$co_headers" \
        $GITHUB_OPENID_CONNECT \
        > /dev/null \
        || (
            error Could not retrieve Chalk JWT token from GitHub OpenID Connect JWT.
            fatal Please make sure GitHub integration is configured in your CrashOverride workspace.
        )
    # grabbing token from headers to avoid dependency on jq
    token=$(header_value "$co_headers" x-chalk-jwt)
    echo "::add-mask::$token"
}

openid_connect_gitlab() {
    if [ -z "$oidc" ]; then
        error GitLab OpenID Connect token is missing.
        error Ensure GitLab job defines id token:
        cat << EOF
<job>:
  id_tokens:
    CHALK_OIDC:
      aud: https://crashoverride.run
EOF
        fatal See https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html
    fi
    info Authenticating to CrashOverride via GitLab OpenID Connect
    co_headers=$(mktemp -t co_jwt.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --header "Authorization: bearer $oidc" \
        --dump-header "$co_headers" \
        $GITLAB_OPENID_CONNECT \
        > /dev/null \
        || (
            error Could not retrieve Chalk JWT token from GitLab OpenID Connect JWT.
            fatal Please make sure GitLab integration is configured in your CrashOverride workspace.
        )
    # grabbing token from headers to avoid dependency on jq
    token=$(header_value "$co_headers" x-chalk-jwt)
}

token_via_openid_connect() {
    if [ -n "${CI:-}" ] && [ -n "${GITHUB_SHA:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        openid_connect_github
    elif [ -n "${CI:-}" ] && [ -n "${GITLAB_CI:-}" ]; then
        openid_connect_gitlab
    else
        fatal Not supported CI system to use OpenID Connect to get CrashOverride JWT token. Pass --token explicitly.
    fi
}

load_custom_profile() {
    info Loading custom Chalk profile from CrashOverride
    headers=$(mktemp -t co_headers.XXXXXX)
    result=$(mktemp -t co_respose.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header "Authorization: bearer $token" \
        --dump-header "$headers" \
        "$PROFILE?chalkVersion=$(chalk_version)&chalkProfileKey=$profile" \
        > "$result" \
        || (
            error Could not retrieve custom Chalk profile.
            fatal "$(cat "$result")"
        )
    # grabbing token from headers to avoid dependency on jq
    component_url=$(header_value "$headers" x-chalk-component-url)
    parameters_url=$(header_value "$headers" x-chalk-component-parameters-url)
    component=$(mktemp -t co_component_XXXXXX).c4m
    parameters=$(mktemp -t co_params_XXXXXX).json
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        "$component_url" \
        > "$component" \
        || (
            error Could not retrieve custom Chalk profile component.
            fatal "$(cat "$component")"
        )
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --header 'Accept: application/json' \
        "$parameters_url" \
        > "$parameters" \
        || (
            error Could not retrieve custom Chalk profile component parameters.
            fatal "$(cat "$parameters")"
        )
    params=- load_config "$component" < "$parameters"
}

# wrapper for calling chalk within the script
chalk() {
    $SUDO chmod +xr "$chalk_path"
    timeout -s KILL "${timeout}s" $SUDO "$chalk_path" --log-level="$log_level" --skip-summary-report --skip-command-report "$@"
}

chalk_version() {
    log_level=none chalk version | grep -i version | head -n1 | awk '{print $5}'
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

get_chalk_path() {
    echo "$prefix/bin/chalk"
}

# download chalk and validate its checksum
download_chalk() {
    name=$(chalk_version_name)
    chalk_tmp=$TMP/$(chalk_version_name)

    if [ -n "$copy_from" ]; then
        info Copying existing Chalk from "$copy_from"
        cp "$copy_from" "$TMP/$name"
        return
    fi

    url=$URL_PREFIX/$(chalk_folder)/$name
    info Downloading Chalk from "$url"
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
            fatal Oh no. Checksum validation failed. Exiting as Chalk binary might of been tampered with
        )
    )
}

# validate downloaded Chalk can run on the system
# and then install it to $chalk_path which should be on PATH
install_chalk() {
    info Checking Chalk version
    chalk_path=$chalk_tmp chalk version
    info Installing Chalk to "$chalk_path"
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
    arch_path=~/.local/chalk/bin/${os}/${arch}/chalk
    info Copying Chalk "$os/$arch" to "$arch_path"
    mkdir -p "$(dirname "$arch_path")"
    cp "$chalk_tmp" "$arch_path"
    chmod +xr "$arch_path"
}

normalize_cosign() {
    if is_installed cosign; then
        # TODO fix in src/configs/attestation.c4m
        info Copying cosign to /tmp for Chalk
        cp "$(which cosign)" /tmp/cosign
    fi
}

# load custom Chalk config
load_config() {
    to_load=$1
    if [ "$params" = "-" ]; then
        chalk load "$to_load" --params
    elif [ -n "$params" ]; then
        echo "$params" | chalk load "$to_load" --params
    else
        chalk load "$to_load"
    fi
    if [ -n "$debug" ]; then
        chalk dump
        chalk dump cache
    fi
}

# add lines to Chalk config
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

# add necessary configs to wrap command with Chalk
add_cmd_exe_to_config() {
    cmd=$1
    path=$2
    folder=$(dirname "$path")
    add_lines_to_chalk \
        "$cmd" \
        "default_command = \"$cmd\"" \
        "${cmd}_exe = \"$folder\""
}

# wrap given command with Chalk
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

    info Wrapping "$existing_path" command with Chalk

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

    # create temporary Chalk copy so that we can adjust its configuration
    # to be able to find the moved binary in the chalkless location
    info Wrapping "$chalked_path" with Chalk
    tmp=$(mktemp -t chalk.XXXXXX)
    $SUDO cp "$chalk_path" "$tmp"
    chalk_path=$tmp add_cmd_exe_to_config "$cmd" "$chalkless_path"
    $SUDO rm "$chalked_path" 2> /dev/null || true
    $SUDO cp "$tmp" "$chalked_path"
    info Using "$chalked_path" will automatically use Chalk now
}

copy_keys() {
    $SUDO cp "$public_key" "$(dirname "$chalk_path")/chalk.pub"
    $SUDO cp "$private_key" "$(dirname "$chalk_path")/chalk.key"
}

help() {
    cat << EOF
Setup Chalk:

* Downloads binary
* Verifies checksum
* Installs to --prefix
* Wraps supported commands (currently docker)

Usage: ${0} [args]

Args:

-h / --help         Show this message
--version=*         Chalk version/commit to download.
                    By default latest version is used.
--load=*            Comma/newline delimited paths/URLs
                    of Chalk components to load.
--params=*          JSON of component params to load.
                    Can be "-" to read params from stdin.
--profile=*         Name of the custom CrashOverride profile
                    to load. Default is 'default'.
--connect           Automatically connect to CrashOverride
                    via OpenID Connect OIDC.
                    Currently supports:
                    * GitHub (requires id-token: write permission)
--oidc=*            When --connect cannot automatically generate
                    OpenID Connect token, OIDC token can be passed
                    directly via a parameter or CHALK_OIDC env var.
                    Currently supports:
                    * GitLab (requires using id_tokens)
--token=*           CrashOverride API token when OpenID Connect
                    cannot be used.
--prefix=*          Where to install Chalk and related
                    binaries. Default is ${prefix}.
--chalk-path=*      Exact path where to install Chalk.
                    Default is $(get_chalk_path).
--no-wrap=*         Do not wrap supported binaries.
--debug             Enable debug mode. This enables trace
                    logs for installed Chalk and will
                    run setup script in verbose mode.
--[no-]overwrite    Whether to overwrite Chalk binary
                    if $(get_chalk_path) already exists.
                    Default is ${overwrite}.
--timeout=*         Timeout for Chalk commands.
                    Default is ${timeout}.
--platforms=*       Download additional Chalk platforms to
                    ~/.local/chalk/bin/{os}/{arch}/chalk.
--public-key=*      Path to signing public key.
--private-key=*     Path to signing private key encrypted with
                    CHALK_PASSWORD env var.
--setup             Run Chalk setup. Also setup automatically runs
                    if --public-key and --private-key are provided.

Args for debugging:

--copy-from=*       Instead of downloading Chalk binary
                    copy it from this path instead.
EOF
    exit "${1:-0}"
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
        --connect)
            connect=true
            ;;
        --profile=*)
            profile=${arg##*=}
            ;;
        --token=*)
            token=${arg##*=}
            token=$(echo "$token" | tr -d '\n')
            ;;
        --oidc=*)
            oidc=${arg##*=}
            oidc=$(echo "$oidc" | tr -d '\n')
            connect=true
            ;;
        --params=*)
            params=${arg##*=}
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
        --setup)
            setup=true
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
        --public-key=*)
            public_key=${arg##*=}
            ;;
        --private-key=*)
            private_key=${arg##*=}
            ;;
        --help | -h)
            help 0
            ;;
        *)
            error unsupported arg "$arg"
            echo
            help 1
            ;;
    esac
done

if ! echo "$PATH" | tr ":" "\n" | grep "$prefix/bin" > /dev/null; then
    fatal "$prefix/bin" is not part of PATH. "--prefix=<prefix>/bin" must be part of PATH
fi

chalk_path=$(get_chalk_path)
chalk_tmp=

if am_owner "$prefix"; then
    SUDO=
else
    if [ -z "$SUDO" ]; then
        fatal sudo is required to install chalk in "$prefix" as current user "'$(id -un)'" does not own it
    fi
fi

if [ "${ACTIONS_STEP_DEBUG:-}" = "true" ]; then
    enable_debug
fi

if [ -z "$token" ] && { [ -n "$connect" ] || [ -n "$oidc" ]; }; then
    token_via_openid_connect
fi

if ! [ -f "$chalk_path" ] || [ -n "$overwrite" ]; then
    if [ -f "$chalk_path" ]; then
        info "$chalk_path" is already installed. overwriting
    fi

    if [ -z "$version" ] || [ "$version" = "latest" ]; then
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

if [ -n "$token" ]; then
    load_custom_profile
fi

for i in $(echo "$load" | tr "," "\n" | tr " " "\n"); do
    if [ -z "$i" ]; then
        continue
    fi
    info Loading custom Chalk config from "$i"
    load_config "$i"
done

if [ -n "$debug" ]; then
    info Debug mode is enabled. Changing default Chalk log level to trace
    params='' load_config https://chalkdust.io/debug.c4m
fi

if [ -n "$password" ] && [ -f "$public_key" ] && [ -f "$private_key" ]; then
    info "Loading signing keys into Chalk"
    copy_keys
    chalk setup
elif [ -n "$setup" ] || [ -n "$token" ]; then
    info "Setting up Chalk attestation"
    chalk setup
fi

if [ -n "$wrap" ]; then
    wrap_cmd docker
fi
