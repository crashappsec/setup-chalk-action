#!/bin/sh
# Runs after a failed chalk setup. When the profile's build policy can block
# this repository, docker build/push must not run without chalk, so a docker
# stub that refuses them is put first on PATH. Workflows commonly mark the
# setup step continue-on-error, which would otherwise let builds run
# unchecked. Always exits 1: the setup did fail.
#
# Usage: policy-guard.sh PREFIX CAN_BLOCK [POLICY_IDS]

set -eu

prefix=$1
can_block=$2
# ids come from a chalkapi header and end up inside the stub script
policy_ids=$(printf '%s' "${3:-}" | tr -cd 'A-Za-z0-9_.@:/ -')

if [ "$can_block" != true ]; then
    echo "::error title=Chalk setup failed::See the 'Set up chalk' step. No build policy can block this repository, so later docker commands run without chalk."
    exit 1
fi

# the real docker: chalk's copy if setup got as far as wrapping it, else the
# first one on PATH outside $prefix/bin
real=
if [ -x "$prefix/chalkless/docker" ]; then
    real=$prefix/chalkless/docker
else
    old_ifs=$IFS
    IFS=:
    for dir in $PATH; do
        if [ "$dir" != "$prefix/bin" ] && [ -x "$dir/docker" ]; then
            real=$dir/docker
            break
        fi
    done
    IFS=$old_ifs
fi

message="Chalk setup failed and build policy ${policy_ids:-of this workspace} can block this repository, so docker build and push are disabled in this job. Fix the 'Set up chalk' step and re-run."

stub=$(mktemp)
cat > "$stub" << EOF
#!/bin/sh
# Installed by setup-chalk-action: $message
real='$real'
EOF
cat >> "$stub" << 'EOF'
sub=
next=
skip=
for arg; do
    if [ -n "$skip" ]; then
        skip=
        continue
    fi
    case "$arg" in
        # docker global options that take a separate value
        -c | --context | -H | --host | -l | --log-level | --config | --tlscacert | --tlscert | --tlskey)
            skip=true
            continue
            ;;
        -*) continue ;;
    esac
    if [ -z "$sub" ]; then
        sub=$arg
        case "$sub" in
            buildx | image | builder) continue ;;
        esac
    else
        next=$arg
    fi
    break
done
case "$sub:$next" in
    build:* | push:* | buildx:build | buildx:bake | image:build | image:push | builder:build)
EOF
cat >> "$stub" << EOF
        echo "::error title=Build policy::$message" >&2
        exit 1
        ;;
esac
EOF
cat >> "$stub" << 'EOF'
if [ -z "$real" ]; then
    echo "docker: command not found" >&2
    exit 127
fi
exec "$real" "$@"
EOF

sudo=
if ! { mkdir -p "$prefix/bin" && [ -w "$prefix/bin" ]; } 2> /dev/null; then
    sudo="sudo -n"
fi
$sudo mkdir -p "$prefix/bin"
$sudo rm -f "$prefix/bin/docker"
$sudo cp "$stub" "$prefix/bin/docker"
$sudo chmod 0755 "$prefix/bin/docker"
rm -f "$stub"

echo "::error title=Build policy::$message"
exit 1
