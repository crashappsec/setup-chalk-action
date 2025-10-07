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

plural() {
    if [ "$1" -gt 1 ]; then
        echo "${2}s"
    else
        echo "${2}"
    fi
}

first_nonempty() {
    for arg; do
        shift
        if [ -n "$arg" ]; then
            echo "$arg"
            return 0
        fi
    done
}

TMP=$(
    first_nonempty \
        "${CHALK_TMP:-}" \
        "${TMPDIR:-}" \
        "${TMP:-}" \
        "/tmp"
)
tmp_files=$(command mktemp -u -p "$TMP")

mktemp() {
    command mktemp -p "$TMP" "$@" | tee -a "$tmp_files"
}

cleanup() {
    if [ -f "$tmp_files" ]; then
        while IFS= read -r f; do
            rm "$f"* || true
        done < "$tmp_files"
        rm "$tmp_files" || true
    fi
}

trap cleanup EXIT INT TERM

is_installed() {
    name=$1
    which "$name" > /dev/null 2>&1
}

os=${os:-$(uname -s)}
arch=${arch:-$(uname -m)}

URL_PREFIX=https://dl.crashoverride.run
SHA256=sha256sum
SUDO=sudo

# version of chalk to download
version=${CHALK_VERSION:-}
# url to fetch latest chalk version
latest_version_url=${CHALK_LATEST_VERSION_URL:-$URL_PREFIX/chalk/current-version.txt}
# which config to load after install
load=${CHALK_LOAD:-}
# json params to load
params=${CHALK_PARAMS:-}
# whether to automatically determine token via openid connect
connect=${CHALK_CONNECT:-}
# saas connect mode - no sensitive tokens are stored in chalk
saas=${CHALK_SAAS:-}
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
# how many attempts in total to retry a command
attempts=${CHALK_ATTEMPTS:-3}
# how long to sleep in-between retryable commands
retry_sleep=${CHALK_RETRY_SLEEP:-1}
# information for signing
password=${CHALK_PASSWORD:-}
public_key=${CHALK_PUBLIC_KEY:-}
private_key=${CHALK_PRIVATE_KEY:-}
# run chalk setup
setup=${CHALK_SETUP:-}

do_help=
chalk_path=
chalk_tmp=

# on osx, sha256sum doesnt exist and instead its shasum
if ! is_installed "$SHA256"; then
    SHA256="shasum -a 256"
fi

if ! is_installed sudo; then
    SUDO=
fi

# timeout is missing by default on mac
if is_installed "timeout"; then
    timeout() {
        command timeout -s KILL "${timeout}s" "$@"
    }
else
    timeout() {
        "$@"
    }
fi

ENTITLEMENTS_HOST=https://entitlements.crashoverride.run
CHALKAPI_HOST=
if [ -n "${__CHALK_TESTING__:-}" ]; then
    warn Beware - chalk is now using test environment which is meant for internal chalk testing only.
    ENTITLEMENTS_HOST=https://entitlements-test.crashoverride.run
fi

retry() {
    # parsing most important args just for prettier retry error logs
    # we care about:
    # * cmd being ran
    # * first positional arg
    cmd=
    first=
    _kwarg=
    for arg; do
        case "$arg" in
            --*)
                _kwarg=true
                ;;
            -*) ;;
            *)
                if [ -z "$_kwarg" ]; then
                    if [ -z "$cmd" ]; then
                        if [ "$arg" != "command" ]; then
                            cmd="$arg"
                        fi
                    elif [ -z "$first" ]; then
                        first="$arg"
                    else
                        break
                    fi
                fi
                _kwarg=
                ;;
        esac
    done
    input=
    # it is possible for all of setup.sh to be executed under stdin pipe
    # so instead we use a custom env var while calling retry to indicate stdin needs to be recorded
    if [ -n "${stdin_pipe:-}" ]; then
        # save stdin so we can safely retry
        # otherwise retry is not equivalent
        input=$(mktemp "$cmd.XXXXXX")
        cat > "$input"
    fi
    _retry() {
        if [ -n "$input" ]; then
            "$@" < "$input"
        else
            "$@"
        fi
    }
    attempted=0
    sleeping=$retry_sleep
    while ! _retry "$@"; do
        attempted=$((attempted + 1))
        if [ "$attempted" -lt "$attempts" ]; then
            error \
                Retrying after "$attempted" "$(plural "$attempted" attempt)" \
                in "$sleeping" "$(plural "$sleeping" second)": \
                "$cmd" "$first"
            sleep "$sleeping"
            sleeping=$((sleeping * 2))
        else
            return 1
        fi
    done
}

curl() {
    retry command curl "$@"
}

wget() {
    retry command wget "$@"
}

first_permissions() {
    path=$1
    format=$2
    while
        ! stat "$path" > /dev/null 2>&1
    do
        path=$(dirname "$path")
    done
    if [ "$os" = "Darwin" ]; then
        # mac uses -f for format instead of -c but on linux -f shows filesystem :shrug:
        stat -f "$format""$path"
    else
        stat -c "$format" "$path"
    fi
}

owner_permissions() {
    path=$1
    first_permissions "$path" "%A" | cut -c 2-4
}

group_permissions() {
    path=$1
    first_permissions "$path" "%A" | cut -c 5-7
}

world_permissions() {
    path=$1
    first_permissions "$path" "%A" | cut -c 8-10
}

am_owner() {
    path=$1
    uid=$(id -u)
    path_uid=$(first_permissions "$path" "%u")
    [ "$uid" = "$path_uid" ]
}

am_group() {
    path=$1
    groups=$(id -G)
    path_group=$(first_permissions "$path" "%g")
    echo "$groups" | grep -qw "$path_group"
}

device_of() {
    path=$1
    first_permissions "$path" "%d"
}

can_rwx() {
    path=$1
    if am_owner "$path" && [ "$(owner_permissions "$path")" = "rwx" ]; then
        return 0
    elif am_group "$path" && [ "$(group_permissions "$path")" = "rwx" ]; then
        return 0
    fi
    world=$(world_permissions "$path")
    # rwt is rwx but with sticky bit like for /tmp
    if [ "$world" = "rwx" ] || [ "$world" = "rwt" ]; then
        return 0
    fi
    return 1
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

set_chalkapi_host_from_headers() {
    # grabbing token from headers to avoid dependency on jq
    CHALKAPI_HOST=$(header_value "$1" x-chalk-api-host)
    if [ -z "$CHALKAPI_HOST" ]; then
        fatal Could not lookup Chalk API host via entitlements service.
    fi
}

openid_connect_github() {
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        error Cannot generate GitHub OpenId Connect JWT Token.
        error Workflow/job "'id-token: write'" permission is missing.
        fatal See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings
    fi
    info Generating GitHub OpenID Connect JWT
    github_jwt=$(mktemp github_jwt.XXXXXX)
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
    if [ -z "$CHALKAPI_HOST" ]; then
        info Looking up Chalk API host via CrashOverride entitlement API from GitHub OpenID Connect JWT.
        entitlement_headers=$(mktemp co_ent_jwt.XXXXXX)
        curl \
            --fail \
            --show-error \
            --silent \
            --location \
            --request POST \
            --header 'Content-Type: application/json' \
            --data-binary @"$github_jwt" \
            --dump-header "$entitlement_headers" \
            "$ENTITLEMENTS_HOST/v0.1/routes/oidc/github" \
            > /dev/null \
            || (
                error Could not lookup Chalk API host from entitlements service via GitHub OpenID Connect JWT.
                fatal Please make sure GitHub integration is configured in your CrashOverride workspace.
            )
        set_chalkapi_host_from_headers "$entitlement_headers"
    fi
    info Authenticating to CrashOverride via GitHub OpenID Connect
    co_headers=$(mktemp co_jwt.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --data-binary @"$github_jwt" \
        --dump-header "$co_headers" \
        "$CHALKAPI_HOST/v0.1/openid-connect/github" \
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
    if [ -z "$CHALKAPI_HOST" ]; then
        info Looking up Chalk API host via CrashOverride entitlement API from GitLab OpenID Connect JWT.
        entitlement_headers=$(mktemp co_ent_jwt.XXXXXX)
        curl \
            --fail \
            --show-error \
            --silent \
            --location \
            --request POST \
            --header 'Content-Type: application/json' \
            --header "Authorization: bearer $oidc" \
            --dump-header "$entitlement_headers" \
            "$ENTITLEMENTS_HOST/v0.1/routes/oidc/gitlab" \
            > /dev/null \
            || (
                error Could not lookup Chalk API host from entitlements service via GitLab OpenID Connect JWT.
                fatal Please make sure GitLab integration is configured in your CrashOverride workspace.
            )
        set_chalkapi_host_from_headers "$entitlement_headers"
    fi
    info Authenticating to CrashOverride via GitLab OpenID Connect
    co_headers=$(mktemp co_jwt.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --header "Authorization: bearer $oidc" \
        --dump-header "$co_headers" \
        "$CHALKAPI_HOST/v0.1/openid-connect/gitlab" \
        > /dev/null \
        || (
            error Could not retrieve Chalk JWT token from GitLab OpenID Connect JWT.
            fatal Please make sure GitLab integration is configured in your CrashOverride workspace.
        )
    # grabbing token from headers to avoid dependency on jq
    token=$(header_value "$co_headers" x-chalk-jwt)
}

token_via_openid_connect() {
    if [ -n "${CI:-}" ] && [ -n "${GITHUB_SHA:-}" ]; then
        openid_connect_github
    elif [ -n "${CI:-}" ] && [ -n "${GITLAB_CI:-}" ]; then
        openid_connect_gitlab
    else
        fatal Not supported CI system to use OpenID Connect to get CrashOverride JWT token. Pass --token explicitly.
    fi
}

ensure_chalkapi_host() {
    if [ -z "$CHALKAPI_HOST" ]; then
        info Looking up Chalk API host from entitlement service via chalk JWT.
        entitlement_headers=$(mktemp entitlement_headers.XXXXXX)
        result=$(mktemp entitlement_respose.XXXXXX)
        curl \
            --fail \
            --show-error \
            --silent \
            --location \
            --request GET \
            --header "Authorization: bearer $token" \
            --dump-header "$entitlement_headers" \
            "$ENTITLEMENTS_HOST/v0.1/routes/chalkapi" \
            > "$result" \
            || (
                error Could not lookup Chalk API host from entitlements service via GitHub OpenID Connect JWT.
                fatal "$(cat "$result")"
            )
        set_chalkapi_host_from_headers "$entitlement_headers"
    fi
}

set_profile_chalk_version() {
    ensure_chalkapi_host
    info Looking up which chalk version to install via Chalk profile from CrashOverride
    result=$(mktemp chalk_version.XXXXXX)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request GET \
        --header "Authorization: bearer $token" \
        "$CHALKAPI_HOST/v0.1/profile/version?chalkProfileKey=$profile" \
        > "$result" \
        || (
            error Could not lookup chalk version to install via Chalk profile.
            fatal "$(cat "$result")"
        )
    version=$(cat "$result")
    info Chalk profile is configured to use version: "$version"
}

load_custom_profile() {
    ensure_chalkapi_host
    info Loading custom Chalk profile from CrashOverride
    headers=$(mktemp co_headers.XXXXXX)
    result=$(mktemp co_respose.XXXXXX)
    chalk_version=$(get_chalk_version)
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header "Authorization: bearer $token" \
        --dump-header "$headers" \
        "$CHALKAPI_HOST/v0.1/profile?chalkVersion=$chalk_version&chalkProfileKey=$profile&os=$os&architecture=$arch&saas=${saas:-false}" \
        > "$result" \
        || (
            error Could not retrieve custom Chalk profile.
            fatal "$(cat "$result")"
        )
    # grabbing token from headers to avoid dependency on jq
    component_url=$(header_value "$headers" x-chalk-component-url)
    parameters_url=$(header_value "$headers" x-chalk-component-parameters-url)
    run_setup=$(header_value "$headers" x-chalk-setup)
    build_observables=$(header_value "$headers" x-chalk-build-observables)
    curiosity_archive=$(header_value "$headers" x-chalk-curiosity-archive)
    component=$(mktemp co_component_XXXXXX).c4m
    parameters=$(mktemp co_params_XXXXXX).json
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
    if [ -z "$saas" ] && [ "$run_setup" = "true" ]; then
        info "Setting up CrashOverride Chalk attestation"
        chalk setup
    fi
    if [ "$build_observables" = "true" ] \
        && [ -n "${GITHUB_OUTPUT:-}" ] \
        && [ -n "$curiosity_archive" ]; then
        info "Enabling build observables for this workflow"
        echo "setup_build_observables=true" >> "$GITHUB_OUTPUT"
        echo "curiosity_archive_url=$curiosity_archive" >> "$GITHUB_OUTPUT"
    fi
}

# wrapper for calling chalk within the script
chalk() {
    $SUDO chmod +xr "$chalk_path"
    timeout $SUDO "$chalk_path" --log-level="$log_level" --skip-summary-report --skip-command-report "$@"
}

get_chalk_version() {
    version=$(log_level=none chalk --no-color version | grep -i version | head -n1 | awk '{print $5}')
    if [ -z "$version" ]; then
        fatal could not determine chalk version
    fi
    echo "$version"
}

# find out latest chalk version
set_latest_version() {
    info Querying latest version of chalk
    version=$(curl -fsSL "$latest_version_url")
    info Latest version is "$version"
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
    wget --quiet --directory-prefix="$TMP" "$url" "$url.sha256" || (
        fatal Could not download "$name". Are you sure this is a valid version?
    )
    if ! [ -f "$chalk_tmp" ]; then
        return 1
    fi
    echo "$chalk_tmp" >> "$tmp_files"
    checksum=$(cat "$chalk_tmp.sha256")
    info Validating sha256 checksum "${checksum%% *}"
    (
        cd "$TMP"
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
    $SUDO chmod +xr "$chalk_tmp"
    $SUDO cp "$chalk_tmp" "$chalk_path"
}

# load custom Chalk config
load_config() {
    to_load=$1
    if [ "$params" = "-" ]; then
        retry chalk load "$to_load" --params
    elif [ -n "$params" ]; then
        echo "$params" | stdin_pipe=true retry chalk load "$to_load" --params
    else
        retry chalk load "$to_load"
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
    config=$(mktemp "chalk_${name}_XXXXXX").c4m
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

    if [ -f "$chalkless_path" ]; then
        warn Using existing "$chalkless_path" as chalkless command. "$0" most likely already ran before.
    else
        $SUDO mkdir -p "$(dirname "$chalkless_path")"
        if am_owner "$existing_path" && [ "$(device_of "$chalkless_path")" = "$(device_of "$existing_path")" ]; then
            # hardlinking requires more permissions
            # so only doing when owning file
            # as well as if both files are in the same file-system
            # otherwise hardlinks cant work so can only copy
            info Hardlinking "$chalkless_path" to "$existing_path"
            $SUDO ln "$existing_path" "$chalkless_path"
        else
            info Copying "$existing_path" to "$chalkless_path"
            $SUDO cp "$existing_path" "$chalkless_path"
        fi
    fi

    # create temporary Chalk copy so that we can adjust its configuration
    # to be able to find the moved binary in the chalkless location
    info Wrapping "$chalked_path" with Chalk
    tmp=$(mktemp chalk.XXXXXX)
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

-h / --help            Show this message
--version=*            Chalk version/commit to download.
                       Default is '${version}'.
                       If empty and --connect is used,
                       version is lookedup from CrashOverride profile.
                       Otherwise default is 'latest'.
--load=*               Comma/newline delimited paths/URLs
                       of Chalk components to load.
--params=*             JSON of component params to load.
                       Can be "-" to read params from stdin.
--profile=*            Name of the custom CrashOverride profile
                       to load. Default is '${profile}'.
--connect              Automatically connect to CrashOverride
                       via OpenID Connect OIDC.
                       Currently supports:
                       * GitHub (requires id-token: write permission)
--oidc=*               When --connect cannot automatically generate
                       OpenID Connect token, OIDC token can be passed
                       directly via a parameter or CHALK_OIDC env var.
                       Currently supports:
                       * GitLab (requires using id_tokens)
--saas                 Connect chalk in SAAS mode where no sensitive
                       tokens are stored in chalk but it can still
                       send reports to SAAS providers CrashOverride workspace.
--token=*              CrashOverride API token when OpenID Connect
                       cannot be used.
--prefix=*             Where to install Chalk and wrapped binaries.
                       <prefix>/bin is expected to be in PATH.
                       Wrapped binariess will be copied to <prefix/chalkless.
                       Default is '${prefix}'.
--chalk-path=*         Exact path where to install Chalk.
                       Default is '$(get_chalk_path)'.
--no-wrap=*            Do not wrap supported binaries.
--debug/-vv            Enable debug mode. This enables trace
                       logs for installed Chalk and will
                       run setup script in verbose mode.
--[no-]overwrite       Whether to overwrite Chalk binary
                       if '$(get_chalk_path)' already exists.
                       Default is '${overwrite}'.
--timeout=*            Timeout for Chalk commands (in seconds).
                       Default is '${timeout}.
--attempts=*           How many times in total retry retryable commands.
                       Default is ${attempts}.
--retry-sleep=*        How long to initally sleep in-between
                       retryable commands (in seconds).
                       Subsequently sleep time is exponentially increased.
                       Default is ${retry_sleep}.
--public-key=*         Path to signing public key.
--private-key=*        Path to signing private key encrypted with
                       CHALK_PASSWORD env var.
--setup                Run Chalk setup. Also setup automatically runs
                       if --public-key and --private-key are provided.
                       Mutually exclusive with --saas as it disables
                       seting up chalk's attestation.
--latest-version-url=* URL to get latest chalk version if
                       --version is not provided.
                       Default is '${latest_version_url}'.
--copy-from=*          Instead of downloading Chalk binary
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
        --latest-version-url=*)
            if [ -n "${arg##*=}" ]; then
                latest_version_url=${arg##*=}
            fi
            ;;
        --load=*)
            load=${arg##*=}
            ;;
        --connect)
            connect=true
            ;;
        --saas)
            saas=true
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
            p=${arg##*=}
            if [ -n "$p" ]; then
                prefix=$p
                prefix=$(echo "$prefix" | sed "s#~#$HOME#" | sed 's/bin$//')
                prefix=$(realpath "$prefix")
            fi
            ;;
        --chalk-path=*)
            chalk_path=${arg##*=}
            ;;
        --no-wrap)
            wrap=
            ;;
        -vv)
            enable_debug
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
        --public-key=*)
            public_key=${arg##*=}
            ;;
        --private-key=*)
            private_key=${arg##*=}
            ;;
        --attempts=*)
            attempts=${arg##*=}
            ;;
        --retry-sleep=*)
            retry_sleep=${arg##*=}
            ;;
        --help | -h)
            do_help=true
            ;;
        *)
            error unsupported arg "$arg"
            echo
            help 1
            ;;
    esac
done

if [ -n "$do_help" ]; then
    help 0
fi

# if wrapping is enabled $prefix/bin should be on PATH
# otherwise wrapped commands will not actually be wrapped
if [ -n "$wrap" ] && ! echo "$PATH" | tr ":" "\n" | grep "$prefix/bin" > /dev/null; then
    fatal "$prefix/bin" is not part of PATH. "--prefix=<prefix>/bin" must be part of PATH
fi

if [ -z "$chalk_path" ]; then
    chalk_path=$(get_chalk_path)
fi

if [ "$(id -u)" = "0" ] || (can_rwx "$prefix" && can_rwx "$chalk_path"); then
    SUDO=
else
    if [ -z "$SUDO" ]; then
        fatal \
            sudo is required to install chalk in "$chalk_path" with prefix="$prefix" \
            as current user "'$(id -un)'" does not own it or doesnt have sufficient permissions
    fi
fi

if [ -n "$debug" ]; then
    enable_debug
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

    if [ -n "$token" ] && [ -z "$version" ]; then
        set_profile_chalk_version
    fi

    if [ -z "$version" ] || [ "$version" = "latest" ]; then
        set_latest_version
    fi

    download_chalk
    install_chalk
else
    info "$chalk_path" is already installed. skipping
fi

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

if [ -z "$saas" ] && [ -n "$password" ] && [ -f "$public_key" ] && [ -f "$private_key" ]; then
    info "Loading signing keys into Chalk"
    copy_keys
    chalk setup
elif [ -z "$saas" ] && [ -n "$setup" ]; then
    info "Setting up Chalk attestation"
    chalk setup
fi

if [ -n "$wrap" ]; then
    wrap_cmd docker
fi
