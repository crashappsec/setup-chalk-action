#!/usr/bin/env sh

set -eu

color() {
    (
        set +x
        _col_name=$1
        shift
        _col_color=
        _col_end=
        if [ -z "${NO_COLOR:-}" ]; then
            case $_col_name in
                yellow)
                    _col_color="\033[0;33m"
                    ;;
                blue)
                    _col_color="\033[0;34m"
                    ;;
                red)
                    _col_color="\033[0;31m"
                    ;;
                green)
                    _col_color="\033[0;32m"
                    ;;
            esac
            _col_end="\033[0m"
        fi
        _col_args="$*"
        printf "$_col_color%s$_col_end" "$_col_args"
    )
}

info() {
    if [ -n "$*" ]; then
        echo "$(color green INFO:)" "$@" > /dev/stderr
    fi
}

warn() {
    if [ -n "$*" ]; then
        echo "$(color yellow WARN:)" "$@" > /dev/stderr
    fi
}

error() {
    if [ -n "$*" ]; then
        echo "$(color red ERROR:)" "$@" > /dev/stderr
    fi
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
    for _fn_arg; do
        shift
        if [ -n "$_fn_arg" ]; then
            echo "$_fn_arg"
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
        while IFS= read -r _cl_f; do
            rm "$_cl_f"* || true
        done < "$tmp_files"
        rm "$tmp_files" || true
    fi
}

trap cleanup EXIT INT TERM

is_installed() {
    command -v "$1" > /dev/null 2>&1
}

os=${os:-$(uname -s)}
arch=${arch:-$(uname -m)}

first_permissions() {
    _fp_path=$1
    _fp_format=$2
    while
        ! stat "$_fp_path" > /dev/null 2>&1
    do
        _fp_path=$(dirname "$_fp_path")
    done
    if [ "$os" = "Darwin" ]; then
        # mac uses -f for format instead of -c but on linux -f shows filesystem :shrug:
        stat -f "$_fp_format" "$_fp_path"
    else
        stat -c "$_fp_format" "$_fp_path"
    fi
}

owner_permissions() {
    _op_path=$1
    first_permissions "$_op_path" "%A" | cut -c 2-4
}

group_permissions() {
    _gp_path=$1
    first_permissions "$_gp_path" "%A" | cut -c 5-7
}

world_permissions() {
    _wp_path=$1
    first_permissions "$_wp_path" "%A" | cut -c 8-10
}

am_owner() {
    _ao_path=$1
    _ao_uid=$(id -u)
    _ao_path_uid=$(first_permissions "$_ao_path" "%u")
    [ "$_ao_uid" = "$_ao_path_uid" ]
}

am_group() {
    _ag_path=$1
    _ag_groups=$(id -G)
    _ag_path_group=$(first_permissions "$_ag_path" "%g")
    echo "$_ag_groups" | grep -qw "$_ag_path_group"
}

device_of() {
    _dv_path=$1
    first_permissions "$_dv_path" "%d"
}

can_rwx() {
    _cr_path=$1
    if am_owner "$_cr_path" && [ "$(owner_permissions "$_cr_path")" = "rwx" ]; then
        return 0
    elif am_group "$_cr_path" && [ "$(group_permissions "$_cr_path")" = "rwx" ]; then
        return 0
    fi
    _cr_world=$(world_permissions "$_cr_path")
    # rwt is rwx but with sticky bit like for /tmp
    if [ "$_cr_world" = "rwx" ] || [ "$_cr_world" = "rwt" ]; then
        return 0
    fi
    return 1
}

URL_PREFIX=https://dl.crashoverride.run
SHA256=sha256sum
SUDO=sudo

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
    # No timeout binary (e.g. a stock macOS install): fall back to running the
    # command directly. This means the --timeout bound is NOT enforced, so a hung
    # Chalk command can run indefinitely. Warn once so operators know the bound is
    # silently dropped rather than assuming it is honored.
    warn "'timeout' command not found; Chalk command timeouts (--timeout) will not be enforced." \
        "Install coreutils (e.g. 'brew install coreutils') to enforce the bound."
    timeout() {
        "$@"
    }
fi

default_prefix() {
    if [ "$(id -u)" != "0" ] && [ -z "$SUDO" ]; then
        for _dp_i in $(echo "$PATH" | tr ":" "\n" | sed 's#/bin$##'); do
            if can_rwx "$_dp_i"; then
                echo "$_dp_i"
                return
            fi
        done
    fi
    echo /usr/local
}

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
# version/ref of the build observables action
observables_version=${CHALK_OBSERVABLES_VERSION:-}
# CrashOverride API token
# Strip any CR/LF the same way the --token CLI arm does: a trailing newline
# (from a secret echoed/pasted with one) must not leak into the
# `Authorization: bearer $token` header, where it would break auth or split
# into a second header line.
token=$(printf '%s' "${CHALK_TOKEN:-}" | tr -d '\r\n')
# OIDC token used to retrieve chalk token (same CR/LF sanitization as --oidc)
oidc=$(printf '%s' "${CHALK_OIDC:-}" | tr -d '\r\n')
# ${prefix}/bin is where script should install chalk and wrapped commands
prefix=${CHALK_PREFIX:-$(default_prefix)}
# whether to overwrite existing chalk binary
overwrite=${CHALK_OVERWRITE:-true}
# whether to replace chalk configuration
config_replace=${CHALK_CONFIG_REPLACE:-}
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

ENTITLEMENTS_HOST=https://entitlements.crashoverride.run
CHALKAPI_HOST=
if [ -n "${__CHALK_TESTING__:-}" ]; then
    warn Beware - chalk is now using test environment which is meant for internal chalk testing only.
    ENTITLEMENTS_HOST=https://entitlements.test.crashoverride.run
fi

retry() {
    # parsing most important args just for prettier retry error logs
    # we care about:
    # * cmd being ran
    # * first positional arg
    _r_cmd=
    _r_first=
    _r_kwarg=
    for _r_arg; do
        case "$_r_arg" in
            --*)
                _r_kwarg=true
                ;;
            -*) ;;
            *)
                if [ -z "$_r_kwarg" ]; then
                    if [ -z "$_r_cmd" ]; then
                        if [ "$_r_arg" != "command" ]; then
                            _r_cmd="$_r_arg"
                        fi
                    elif [ -z "$_r_first" ]; then
                        _r_first="$_r_arg"
                    else
                        break
                    fi
                fi
                _r_kwarg=
                ;;
        esac
    done
    _r_input=
    # it is possible for all of setup.sh to be executed under stdin pipe
    # so instead we use a custom env var while calling retry to indicate stdin needs to be recorded
    if [ -n "${stdin_pipe:-}" ]; then
        # save stdin so we can safely retry
        # otherwise retry is not equivalent
        _r_input=$(mktemp "$_r_cmd.XXXXXX")
        cat > "$_r_input"
    fi
    _retry() {
        if [ -n "$_r_input" ]; then
            "$@" < "$_r_input"
        else
            "$@"
        fi
    }
    _r_attempted=0
    _r_sleeping=$retry_sleep
    while ! _retry "$@"; do
        _r_attempted=$((_r_attempted + 1))
        if [ "$_r_attempted" -lt "$attempts" ]; then
            error \
                Retrying after "$_r_attempted" "$(plural "$_r_attempted" attempt)" \
                in "$_r_sleeping" "$(plural "$_r_sleeping" second)": \
                "$_r_cmd" "$_r_first"
            sleep "$_r_sleeping"
            _r_sleeping=$((_r_sleeping * 2))
        else
            return 1
        fi
    done
}

get_kwarg() {
    _gk_opt="$1"
    shift
    _gk_default="$1"
    shift
    _gk_value="$_gk_default"
    for _gk_arg; do
        shift
        case "$_gk_arg" in
            "$_gk_opt")
                _gk_value=$1
                break
                ;;
            *) ;;

        esac
    done
    echo "$_gk_value"
}

first_arg() {
    for _fa_arg; do
        shift
        case "$_fa_arg" in
            -*) ;;
            *)
                echo "$_fa_arg"
                ;;
        esac
    done
}

if ! is_installed curl; then
    curl() {
        fatal curl is not installed
    }
else
    _CURL_UA_BASE=
    curl() {
        if [ -z "$_CURL_UA_BASE" ]; then
            # curl[/<version>] [setup-chalk-action-commit/<ref>] [setup-hash/<hash>]
            _curl_version=$(command curl --version 2> /dev/null | awk 'NR==1{print $2}')
            if [ -n "$_curl_version" ]; then
                _CURL_UA_BASE="curl/$_curl_version"
            else
                _CURL_UA_BASE="curl"
            fi
            if [ -n "${GITHUB_ACTION_PATH:-}" ]; then
                _CURL_UA_BASE="$_CURL_UA_BASE setup-chalk-action-ref/$(basename "$GITHUB_ACTION_PATH")"
                if is_installed git; then
                    _curl_commit=$(git -c safe.directory="$GITHUB_ACTION_PATH" -C "$GITHUB_ACTION_PATH" --no-pager log -n1 --pretty=format:%H 2> /dev/null)
                    if [ -n "$_curl_commit" ]; then
                        _CURL_UA_BASE="$_CURL_UA_BASE setup-chalk-action-commit/$_curl_commit"
                    fi
                fi
            elif is_installed git; then
                case "$0" in
                    *.sh)
                        if [ -f "$0" ] && git -C "$(dirname "$0")" ls-files --error-unmatch "$0" > /dev/null 2>&1; then
                            _curl_commit=$(git -C "$(dirname "$0")" --no-pager log -n1 --pretty=format:%H 2> /dev/null)
                            if [ -n "$_curl_commit" ]; then
                                _CURL_UA_BASE="$_CURL_UA_BASE setup-chalk-action-commit/$_curl_commit"
                            fi
                        fi
                        ;;
                esac
            fi
            case "$0" in
                *.sh)
                    if [ -f "$0" ]; then
                        _curl_hash=$($SHA256 "$0" 2> /dev/null | awk '{print $1}')
                        if [ -n "$_curl_hash" ]; then
                            _CURL_UA_BASE="$_CURL_UA_BASE setup-hash/$_curl_hash"
                        fi
                    fi
                    ;;
            esac
        fi
        _CURL_UA="$_CURL_UA_BASE${version:+ chalk/$version}"
        _curl_tmperr=$(mktemp curl_err.XXXXXX)
        _curl_url=$(first_arg "$@")
        # --write-out '%{http_code}' requires --output to avoid mixing the
        # status code into the body. If the caller didn't pass --output,
        # buffer to a temp file and cat it on success so the API is transparent.
        _curl_output=$(get_kwarg --output "" "$@")
        _curl_has_output=true
        if [ -z "$_curl_output" ]; then
            _curl_has_output=
            _curl_output=$(mktemp curl_out.XXXXXX)
            set -- "$@" "--output" "$_curl_output"
        fi
        if ! _curl_http_code=$(
            command curl --write-out '%{http_code}' -A "$_CURL_UA" "$@" 2> "$_curl_tmperr"
        ); then
            # Transport error (DNS, timeout, connection refused): copy stderr to
            # both the console and the output file so fatal_curl can surface it.
            cat "$_curl_tmperr" >&2
            cat "$_curl_tmperr" > "$_curl_output"
            return 1
        fi
        case "$_curl_http_code" in
            [45]*)
                error "HTTP error with status $_curl_http_code @ $_curl_url"
                return 22
                ;;
        esac
        if [ -z "$_curl_has_output" ]; then
            cat "$_curl_output"
        fi
        return 0
    }
fi

# curl wrapper that fatally exits on any HTTP or transport failure.
#
# Usage:  fatal_curl [MSG ...] -- CURL_ARGS...
#   MSG        Zero or more lines emitted via `error` before the fatal.
#              Separated from curl args by the literal "--" sentinel.
#   CURL_ARGS  Forwarded verbatim to curl(), including any --output/-o.
#
# On failure, context messages are printed then the function fatals with the
# server response body (or the transport error text when curl itself fails).
# Retry lives here; the bare curl() above is intentionally un-retried.
fatal_curl() {
    _fc_error_msgs=
    for _fc_arg; do
        shift
        case "$_fc_arg" in
            --)
                break
                ;;
            *)
                _fc_error_msgs="${_fc_error_msgs}${_fc_arg}
"
                ;;
        esac
    done
    _fc_url=$(first_arg "$@")
    _fc_output=$(get_kwarg --output "" "$@")
    if ! retry curl "$@"; then
        printf '%s' "$_fc_error_msgs" | while IFS= read -r _fc_error_msg; do
            error "$_fc_error_msg"
        done
        if [ -n "$_fc_output" ]; then
            fatal "$(cat "$_fc_output")"
        else
            fatal curl "$_fc_url"
        fi
    fi
}

# optional_header_value FILE NAME
# Print the value of header NAME from the dumped-header FILE, or an empty
# string when the header is absent. Callers that require the header must check
# the result in the parent shell: `[ -z "$v" ] && fatal "..."`.
optional_header_value() {
    grep -i "$2" < "$1" | awk '{print $2}' | tr -d '\r\n'
}

enable_debug() {
    set -x
    log_level=trace
    debug=true
}

set_chalkapi_host_from_headers() {
    # grab the Chalk API host from the response headers to avoid a dependency on jq
    CHALKAPI_HOST=$(optional_header_value "$1" x-chalk-api-host)
    [ -n "$CHALKAPI_HOST" ] || fatal "Could not lookup Chalk API host via entitlements service."
}

openid_connect_github() {
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        error Cannot generate GitHub OpenId Connect JWT Token.
        error Workflow/job "'id-token: write'" permission is missing.
        fatal See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings
    fi
    info Generating GitHub OpenID Connect JWT
    _ocg_jwt=$(mktemp github_jwt.XXXXXX)
    fatal_curl \
        "Cannot generate GitHub OpenId Connect JWT Token." \
        "Please make sure workflow/job has 'id-token: write' permission." \
        "See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings" \
        -- \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://crashoverride.run" \
        --show-error \
        --silent \
        --location \
        --header "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        --output "$_ocg_jwt"
    if [ -z "$CHALKAPI_HOST" ]; then
        info Looking up Chalk API host via CrashOverride entitlement API from GitHub OpenID Connect JWT.
        _ocg_ent_headers=$(mktemp co_ent_jwt.XXXXXX)
        fatal_curl \
            "Could not lookup Chalk API host from entitlements service via GitHub OpenID Connect JWT." \
            "Please make sure GitHub integration is configured in your CrashOverride workspace." \
            -- \
            "$ENTITLEMENTS_HOST/v0.1/routes/oidc/github?verbose=${debug:-false}" \
            --show-error \
            --silent \
            --location \
            --request POST \
            --header 'Content-Type: application/json' \
            --data-binary @"$_ocg_jwt" \
            --dump-header "$_ocg_ent_headers" \
            > /dev/null
        set_chalkapi_host_from_headers "$_ocg_ent_headers"
    fi
    info Authenticating to CrashOverride via GitHub OpenID Connect
    _ocg_co_headers=$(mktemp co_jwt.XXXXXX)
    fatal_curl \
        "Could not retrieve Chalk JWT token from GitHub OpenID Connect JWT." \
        "Please make sure GitHub integration is configured in your CrashOverride workspace." \
        -- \
        "$CHALKAPI_HOST/v0.1/openid-connect/github?verbose=${debug:-false}" \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --data-binary @"$_ocg_jwt" \
        --dump-header "$_ocg_co_headers" \
        > /dev/null
    # grabbing token from headers to avoid dependency on jq
    token=$(optional_header_value "$_ocg_co_headers" x-chalk-jwt)
    [ -z "$token" ] && fatal "Could not find header x-chalk-jwt from response"
    echo "::add-mask::$token"
}

openid_connect_gitlab() {
    # The GitLab OIDC token ($oidc) and the Chalk JWT retrieved below are
    # secrets. Unlike GitHub, GitLab has no `::add-mask::` equivalent (that is a
    # GitHub Actions runner directive), so under debug tracing (set -x, enabled
    # by enable_debug) they would otherwise be printed on the traced
    # `Authorization: bearer` command lines and the `token=...` assignment and
    # leak into the job log. Disable xtrace for the whole credential exchange
    # and restore the previous state afterwards so the secrets are never traced.
    case $- in
        *x*) _ocgl_xtrace=1 ;;
        *) _ocgl_xtrace= ;;
    esac
    set +x
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
        _ocgl_ent_headers=$(mktemp co_ent_jwt.XXXXXX)
        fatal_curl \
            "Could not lookup Chalk API host from entitlements service via GitLab OpenID Connect JWT." \
            "Please make sure GitLab integration is configured in your CrashOverride workspace." \
            -- \
            "$ENTITLEMENTS_HOST/v0.1/routes/oidc/gitlab?verbose=${debug:-false}" \
            --show-error \
            --silent \
            --location \
            --request POST \
            --header 'Content-Type: application/json' \
            --header "Authorization: bearer $oidc" \
            --dump-header "$_ocgl_ent_headers" \
            > /dev/null
        set_chalkapi_host_from_headers "$_ocgl_ent_headers"
    fi
    info Authenticating to CrashOverride via GitLab OpenID Connect
    _ocgl_co_headers=$(mktemp co_jwt.XXXXXX)
    fatal_curl \
        "Could not retrieve Chalk JWT token from GitLab OpenID Connect JWT." \
        "Please make sure GitLab integration is configured in your CrashOverride workspace." \
        -- \
        "$CHALKAPI_HOST/v0.1/openid-connect/gitlab?verbose=${debug:-false}" \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header 'Content-Type: application/json' \
        --header "Authorization: bearer $oidc" \
        --dump-header "$_ocgl_co_headers" \
        > /dev/null
    # grabbing token from headers to avoid dependency on jq
    token=$(optional_header_value "$_ocgl_co_headers" x-chalk-jwt)
    [ -z "$token" ] && fatal "Could not find header x-chalk-jwt from response"
    if [ -n "$_ocgl_xtrace" ]; then set -x; fi
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
        _ech_headers=$(mktemp entitlement_headers.XXXXXX)
        fatal_curl \
            "Could not lookup Chalk API host from entitlements service via chalk JWT." \
            -- \
            "$ENTITLEMENTS_HOST/v0.1/routes/chalkapi?verbose=${debug:-false}" \
            --show-error \
            --silent \
            --location \
            --request GET \
            --header "Authorization: bearer $token" \
            --dump-header "$_ech_headers" \
            > /dev/null
        set_chalkapi_host_from_headers "$_ech_headers"
    fi
}

set_profile_chalk_version() {
    ensure_chalkapi_host
    info Looking up which chalk version to install via Chalk profile from CrashOverride
    _spv_result=$(mktemp chalk_version.XXXXXX)
    fatal_curl \
        "Could not lookup chalk version to install via Chalk profile." \
        -- \
        "$CHALKAPI_HOST/v0.1/profile/version?chalkProfileKey=$profile&verbose=${debug:-false}" \
        --show-error \
        --silent \
        --location \
        --request GET \
        --header "Authorization: bearer $token" \
        --output "$_spv_result"
    version=$(tr -d '\r\n' < "$_spv_result")
    info Chalk profile is configured to use version: "$version"
}

load_custom_profile() {
    ensure_chalkapi_host
    info Loading custom Chalk profile from CrashOverride
    _lcp_headers=$(mktemp co_headers.XXXXXX)
    _lcp_chalk_version=$(get_chalk_version)
    _lcp_query="chalkVersion=$_lcp_chalk_version&chalkProfileKey=$profile&os=$os&architecture=$arch&saas=${saas:-false}&verbose=${debug:-false}"
    _lcp_curiosity_rc=
    case "$observables_version" in
        curiosity-rc-*)
            _lcp_curiosity_rc=${observables_version#curiosity-rc-}
            _lcp_curiosity_rc=${_lcp_curiosity_rc#v}
            ;;
    esac
    if [ -n "$_lcp_curiosity_rc" ]; then
        _lcp_query="$_lcp_query&curiosityReleaseCandidate=$_lcp_curiosity_rc"
    fi
    fatal_curl \
        "Could not retrieve custom Chalk profile." \
        -- \
        "$CHALKAPI_HOST/v0.1/profile?$_lcp_query" \
        --show-error \
        --silent \
        --location \
        --request POST \
        --header "Authorization: bearer $token" \
        --dump-header "$_lcp_headers" \
        > /dev/null
    # parse the component/parameter URLs and feature flags from the response headers to avoid a dependency on jq
    _lcp_component_url=$(optional_header_value "$_lcp_headers" x-chalk-component-url)
    _lcp_params_url=$(optional_header_value "$_lcp_headers" x-chalk-component-parameters-url)
    [ -z "$_lcp_component_url" ] && fatal "Could not find header x-chalk-component-url from response"
    [ -z "$_lcp_params_url" ] && fatal "Could not find header x-chalk-component-parameters-url from response"
    _lcp_run_setup=$(optional_header_value "$_lcp_headers" x-chalk-setup)
    _lcp_build_obs=$(optional_header_value "$_lcp_headers" x-chalk-build-observables)
    _lcp_curiosity_archive=$(optional_header_value "$_lcp_headers" x-chalk-curiosity-archive)
    _lcp_curiosity_home=$(optional_header_value "$_lcp_headers" x-chalk-curiosity-home)
    _lcp_component=$(mktemp co_component_XXXXXX).c4m
    _lcp_params_file=$(mktemp co_params_XXXXXX).json
    fatal_curl \
        "Could not retrieve custom Chalk profile component." \
        -- \
        "$_lcp_component_url" \
        --show-error \
        --silent \
        --location \
        --output "$_lcp_component"
    fatal_curl \
        "Could not retrieve custom Chalk profile component parameters." \
        -- \
        "$_lcp_params_url" \
        --show-error \
        --silent \
        --location \
        --header 'Accept: application/json' \
        --output "$_lcp_params_file"
    params=- load_config "$_lcp_component" < "$_lcp_params_file"
    if [ -z "$saas" ] && [ "$_lcp_run_setup" = "true" ]; then
        info "Setting up CrashOverride Chalk attestation"
        chalk setup
    fi
    if [ "$_lcp_build_obs" = "true" ] \
        && [ -n "${GITHUB_OUTPUT:-}" ] \
        && [ -n "$_lcp_curiosity_archive" ]; then
        info "Enabling build observables for this workflow"
        echo "setup_build_observables=true" >> "$GITHUB_OUTPUT"
        echo "curiosity_archive_url=$_lcp_curiosity_archive" >> "$GITHUB_OUTPUT"
        _lcp_obs_version=${observables_version:-main}
        if [ -n "$_lcp_curiosity_rc" ]; then
            _lcp_obs_version="v$_lcp_curiosity_rc"
        fi
        echo "observables_action_version=${_lcp_obs_version:-main}" >> "$GITHUB_OUTPUT"
        echo "curiosity_home=${_lcp_curiosity_home:-/mnt/curiosity}" >> "$GITHUB_OUTPUT"
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
    _slv_result=$(mktemp latest_version.XXXXXX)
    fatal_curl \
        "Could not query latest chalk version from $latest_version_url" \
        -- \
        "$latest_version_url" \
        -sSL \
        --output "$_slv_result"
    version=$(tr -d '\r\n' < "$_slv_result")
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
    _dc_name=$(chalk_version_name)
    chalk_tmp=$TMP/$(chalk_version_name)

    if [ -n "$copy_from" ]; then
        info Copying existing Chalk from "$copy_from"
        cp "$copy_from" "$TMP/$_dc_name"
        return
    fi

    _dc_url=$URL_PREFIX/$(chalk_folder)/$_dc_name
    info Downloading Chalk from "$_dc_url"
    rm -f "$TMP/$_dc_name" "$TMP/$_dc_name.sha256"
    fatal_curl \
        "Could not download $_dc_name. Are you sure this is a valid version?" \
        -- \
        "$_dc_url" \
        --show-error \
        --silent \
        --location \
        --output "$TMP/$_dc_name"
    fatal_curl \
        "Could not download checksum to validate $_dc_name integrity" \
        -- \
        "$_dc_url.sha256" \
        --show-error \
        --silent \
        --location \
        --output "$TMP/$_dc_name.sha256"
    if ! [ -f "$chalk_tmp" ]; then
        return 1
    fi
    echo "$chalk_tmp" >> "$tmp_files"
    _dc_checksum=$(cat "$chalk_tmp.sha256")
    info Validating sha256 checksum "${_dc_checksum%% *}"
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
    if [ -n "$config_replace" ]; then
        set -- "$@" "--replace"
        config_replace=
    fi
    if [ "$params" = "-" ]; then
        stdin_pipe=true retry chalk load "$@" --params
    elif [ -n "$params" ]; then
        echo "$params" | stdin_pipe=true retry chalk load "$@" --params
    else
        retry chalk load "$@"
    fi
    if [ -n "$debug" ]; then
        chalk dump
        chalk dump cache
    fi
}

# add lines to Chalk config
add_lines_to_chalk() {
    _alc_name=$1
    shift
    _alc_config=$(mktemp "chalk_${_alc_name}_XXXXXX").c4m
    touch "$_alc_config"
    for _alc_i; do
        echo "$_alc_i" >> "$_alc_config"
    done
    chalk load "$_alc_config"
    if [ -n "$debug" ]; then
        chalk dump
        chalk dump cache
    fi
}

# add necessary configs to wrap command with Chalk
add_cmd_exe_to_config() {
    _acc_cmd=$1
    _acc_path=$2
    _acc_folder=$(dirname "$_acc_path")
    add_lines_to_chalk \
        "$_acc_cmd" \
        "default_command = \"$_acc_cmd\"" \
        "${_acc_cmd}_exe = \"$_acc_folder\""
}

# wrap given command with Chalk
wrap_cmd() {
    _wc_cmd=$1

    if ! is_installed "$_wc_cmd"; then
        return
    fi

    _wc_existing_path=$(command -v "$_wc_cmd")
    _wc_chalked_path="$prefix/bin/$_wc_cmd"
    _wc_chalkless_path="$prefix/chalkless/$_wc_cmd"

    if [ -z "$_wc_existing_path" ]; then
        warn Skipping wrapping "$_wc_cmd" as it is not installed
        return 0
    fi

    info Wrapping "$_wc_existing_path" command with Chalk

    if [ -f "$_wc_chalkless_path" ]; then
        warn Using existing "$_wc_chalkless_path" as chalkless command. "$0" most likely already ran before.
    else
        $SUDO mkdir -p "$(dirname "$_wc_chalkless_path")"
        if am_owner "$_wc_existing_path" && [ "$(device_of "$_wc_chalkless_path")" = "$(device_of "$_wc_existing_path")" ]; then
            # hardlinking requires more permissions
            # so only doing when owning file
            # as well as if both files are in the same file-system
            # otherwise hardlinks cant work so can only copy
            info Hardlinking "$_wc_chalkless_path" to "$_wc_existing_path"
            $SUDO ln "$_wc_existing_path" "$_wc_chalkless_path"
        else
            info Copying "$_wc_existing_path" to "$_wc_chalkless_path"
            $SUDO cp "$_wc_existing_path" "$_wc_chalkless_path"
        fi
    fi

    # create temporary Chalk copy so that we can adjust its configuration
    # to be able to find the moved binary in the chalkless location
    info Wrapping "$_wc_chalked_path" with Chalk
    _wc_tmp=$(mktemp chalk.XXXXXX)
    $SUDO cp "$chalk_path" "$_wc_tmp"
    chalk_path=$_wc_tmp add_cmd_exe_to_config "$_wc_cmd" "$_wc_chalkless_path"
    $SUDO rm "$_wc_chalked_path" 2> /dev/null || true
    $SUDO cp "$_wc_tmp" "$_wc_chalked_path"
    info Using "$_wc_chalked_path" will automatically use Chalk now
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
* Installs to --prefix/bin
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
--no-wrap              Do not wrap supported binaries.
--debug/-vv            Enable debug mode. This enables trace
                       logs for installed Chalk and will
                       run setup script in verbose mode.
--[no-]overwrite       Whether to overwrite Chalk binary
                       if '$(get_chalk_path)' already exists.
                       Default is '${overwrite}'.
--[no]-config-replace  When loading configurations into chalk,
                       pass '--replace' which will replace existing configurations.
                       Default is '${config_replace}'.
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

# has_value succeeds (returns 0) when the next positional token "$1" is a real
# value rather than another flag. A leading "--" means "$1" is the next flag
# (so the current flag has no value of its own); no args left likewise means no
# value. Pass 1 below uses `! has_value` to append an empty placeholder value
# after any "--flag" that was given without one.
has_value() {
    if [ $# -eq 0 ]; then
        return 1
    fi
    case "$1" in
        --*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# Pass 1 of 2: normalize every argument into a fixed "<flag> <value>" 2-token
# shape. All of these spellings
#     --version=1   --version 1   --version= 1   --version =1   --version = 1
# are rewritten to exactly two tokens: "--version" "1". A "--flag" given with no
# value (bare --version, or a value-less flag like --connect/--saas) is rewritten
# to "--flag" "" -- an empty placeholder value is always appended so that Pass 2
# can unconditionally consume a value token for every long flag. Args are rotated
# in place: `shift` drops the original token off the front and `set -- "$@" ...`
# appends the normalized token(s) to the back, so after $# iterations only
# normalized tokens remain. Single-dash flags (-vv, -h) take no value and are NOT
# normalized -- they pass through unchanged via the *) arm as a single token.
for arg; do
    shift
    case "$arg" in
        # bare "=" (from "--flag = value"): the "=" arrived as its own token, so
        # drop it, appending a placeholder if no real value follows.
        =)
            if ! has_value "$@"; then
                set -- "$@" ""
            fi
            ;;
        # "--flag=" (trailing "="; from "--flag= value"): emit the flag, then a
        # real value if one follows else an empty placeholder.
        --*=)
            set -- "$@" "${arg%%=*}"
            if ! has_value "$@"; then
                set -- "$@" ""
            fi
            ;;
        # "=value" (from "--flag =value"): emit just the value; the flag itself
        # was emitted when the preceding "--flag" token matched the --*) arm.
        =*)
            set -- "$@" "${arg#*=}"
            ;;
        # "--flag=value": split the single token into flag and value.
        --*=*)
            set -- "$@" "${arg%%=*}" "${arg#*=}"
            ;;
        # "--flag" (no "="): emit the flag, then a real value if the next token
        # is one else an empty placeholder.
        --*)
            set -- "$@" "$arg"
            if ! has_value "$@"; then
                set -- "$@" ""
            fi
            ;;
        # positional or single-dash token (e.g. -vv, -h): pass through unchanged.
        *)
            set -- "$@" "$arg"
            ;;
    esac
done

# Pass 2 of 2: consume the normalized tokens. Because Pass 1 guaranteed every
# long "--flag" is followed by exactly one value token (a real value or the ""
# placeholder), each --flag consumes TWO tokens per iteration:
#   * the `shift; n=$((n - 1))` just below consumes the flag token (into $arg);
#   * the first `case "$arg"` reads that flag's value from $1 WITHOUT shifting;
#   * the trailing `case "$arg" in --*)` at the bottom of the loop consumes the
#     value token with a SECOND `shift; n=$((n - 1))`.
# Single-dash flags (-vv, -h) have no value token, do not match that trailing
# --*) arm, and so consume only one token. The two shift sites must stay in
# sync: the flag token is dropped at the top, its value token at the bottom.
n=$#
while [ "$n" -gt 0 ]; do
    arg=${1:-}
    shift
    n=$((n - 1))
    case "$arg" in
        --version)
            version=$1
            ;;
        --latest-version-url)
            latest_version_url=${1:-$latest_version_url}
            ;;
        --load)
            load=$1
            ;;
        --connect)
            connect=true
            ;;
        --saas)
            saas=true
            ;;
        --profile)
            profile=${1:-$profile}
            ;;
        --token)
            token=$(echo "$1" | tr -d '\r\n')
            ;;
        --oidc)
            oidc=$(echo "$1" | tr -d '\r\n')
            connect=true
            ;;
        --params)
            params=$1
            ;;
        --prefix)
            prefix=$(echo "${1:-$prefix}" | sed "s#~#$HOME#" | sed 's/bin$//')
            prefix=$(realpath "$prefix")
            ;;
        --chalk-path)
            chalk_path=$(realpath "$1")
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
        --config-replace)
            config_replace=true
            ;;
        --no-config-replace)
            config_replace=
            ;;
        --copy-from)
            copy_from=$1
            ;;
        --timeout)
            timeout=${1:-$timeout}
            ;;
        --public-key)
            public_key=$1
            ;;
        --private-key)
            private_key=$1
            ;;
        --attempts)
            attempts=$1
            ;;
        --retry-sleep)
            retry_sleep=${1:-$retry_sleep}
            ;;
        --help | -h)
            do_help=true
            ;;
        *)
            error unsupported arg "'$arg'"
            echo
            help 1
            ;;
    esac
    # Consume the value token that Pass 1 guaranteed follows every long "--flag"
    # (its real value, or the "" placeholder). This is the second of the two
    # tokens each --flag consumes -- see the Pass 2 header comment above.
    case "$arg" in
        --*)
            n=$((n - 1))
            shift
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
