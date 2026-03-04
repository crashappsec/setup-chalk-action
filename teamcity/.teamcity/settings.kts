import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script

version = "2024.12"

project {
    buildType(ChalkBuild)
}

object ChalkBuild : BuildType({
    name = "Build with Chalk"

    params {
        param("chalk.version", "0.6.5")
        param("chalk.profile", "default")
        param("chalk.prefix", "/usr/local")
        password("env.CHALK_TOKEN", "credentialsJSON:chalk-token-id",
            label = "Chalk API Token",
            description = "CrashOverride API token — store in TeamCity credentials store")
    }

    steps {
        script {
            name = "Install Chalk"
            scriptContent = """
                #!/usr/bin/env bash
                set -eu

                curl -fsSL \
                    "https://raw.githubusercontent.com/crashappsec/setup-chalk-action/main/setup.sh" \
                    -o /tmp/chalk-setup.sh
                chmod +x /tmp/chalk-setup.sh

                CHALK_FLAGS=""
                [ -n "%chalk.version%" ] && CHALK_FLAGS="${'$'}CHALK_FLAGS --version=%chalk.version%"
                [ "%chalk.profile%" != "default" ] && CHALK_FLAGS="${'$'}CHALK_FLAGS --profile=%chalk.profile%"

                CHALK_PREFIX="%chalk.prefix%" \
                CHALK_TOKEN="%env.CHALK_TOKEN%" \
                    /tmp/chalk-setup.sh ${'$'}CHALK_FLAGS

                "%chalk.prefix%/bin/chalk" --version
                rm -f /tmp/chalk-setup.sh
            """.trimIndent()
        }

        script {
            name = "Build (chalk-wrapped Docker)"
            scriptContent = """
                export PATH="%chalk.prefix%/bin:${'$'}PATH"
                docker build -t myapp:%build.number% .
            """.trimIndent()
        }
    }

    requirements {
        contains("teamcity.agent.jvm.os.name", "Linux")
    }
})
