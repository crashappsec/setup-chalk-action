# chalk-jenkins

A Jenkins Shared Library for installing and configuring [Chalk](https://crashoverride.run) in your Jenkins pipelines.

## Usage

```groovy
@Library('chalk-jenkins@nettrino/expandbuildpipes') _

pipeline {
    agent { label 'linux' }

    environment {
        CHALK_TOKEN = credentials('chalk-api-token')
    }

    stages {
        stage('Install Chalk') {
            steps {
                setupChalk(version: '0.6.5')
            }
        }
        stage('Build') {
            steps {
                sh 'docker build -t myapp:latest .'
            }
        }
    }
}
```

## Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `version` | String | `''` | Chalk version (empty = latest) |
| `load` | String | `''` | Config URL(s) to load |
| `connect` | Boolean | `false` | Connect to CrashOverride |
| `profile` | String | `'default'` | CrashOverride profile name |
| `prefix` | String | `${WORKSPACE}/chalk-home` | Install prefix |
| `token` | String | `env.CHALK_TOKEN` | API token |

## Setup

1. In Jenkins: Manage Jenkins → Configure System → Global Pipeline Libraries
   - Name: `chalk-jenkins`
   - Default version: `nettrino/expandbuildpipes`
   - SCM: Git, URL: `https://github.com/crashappsec/setup-chalk-action`
   - Library Path: `jenkins/`
2. Add credential: Kind=Secret text, ID=`chalk-api-token`, value=your Chalk token

> **Production:** Create a dedicated repo `chalk-jenkins`, push the contents
> of this directory there, and update the library URL to
> `https://github.com/crashappsec/chalk-jenkins` with default version `main`.
> Remove the Library Path setting.
