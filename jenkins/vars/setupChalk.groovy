/**
 * setupChalk - Install and configure Chalk in a Jenkins pipeline step.
 *
 * @param config Map of options:
 *   version  (String)  Chalk version to install. Default: '' (latest)
 *   load     (String)  Config URL(s) to load. Default: ''
 *   connect  (Boolean) Connect to CrashOverride via OIDC-like flow. Default: false
 *   profile  (String)  CrashOverride profile. Default: 'default'
 *   prefix   (String)  Install prefix. Default: "${WORKSPACE}/chalk-home"
 *   token    (String)  API token. Default: env.CHALK_TOKEN
 */
def call(Map config = [:]) {
    def version = config.get('version', '')
    def load    = config.get('load', '')
    def connect = config.get('connect', false)
    def profile = config.get('profile', 'default')
    def prefix  = config.get('prefix', "${env.WORKSPACE}/chalk-home")
    def token   = config.get('token', env.CHALK_TOKEN ?: '')

    def flags = []
    if (version) flags << "--version=${version}"
    if (load)    flags << "--load=${load}"
    if (connect) flags << '--connect'
    if (profile) flags << "--profile=${profile}"
    def flagStr = flags.join(' ')

    sh """
        set -eu
        mkdir -p "${prefix}/bin"

        echo "Downloading chalk setup script..."
        curl -fsSL \\
            "https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh" \\
            -o /tmp/chalk-setup.sh
        chmod +x /tmp/chalk-setup.sh

        echo "Installing Chalk..."
        CHALK_PREFIX="${prefix}" \\
        CHALK_TOKEN="${token}" \\
            /tmp/chalk-setup.sh ${flagStr}

        echo "Chalk installed:"
        "${prefix}/bin/chalk" --version || chalk --version
    """.stripIndent()

    env.PATH = "${prefix}/bin:${env.PATH}"
    echo "Chalk is now available on PATH: ${prefix}/bin"
}
