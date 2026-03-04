FROM jenkins/jenkins:lts-jdk17

# Install plugins as jenkins user first (plugin-cli expects jenkins user)
RUN jenkins-plugin-cli --plugins \
    configuration-as-code \
    workflow-aggregator \
    workflow-cps \
    git \
    job-dsl

USER root

# Install python3 for local HTTP file server
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

# Pre-create directories writable by jenkins user
RUN mkdir -p /var/jenkins_library_repo && chown jenkins:jenkins /var/jenkins_library_repo

# Copy init and entrypoint scripts
COPY init-library-repo.sh /usr/local/bin/init-library-repo.sh
COPY entrypoint.sh /usr/local/bin/custom-entrypoint.sh
RUN chmod +x /usr/local/bin/init-library-repo.sh /usr/local/bin/custom-entrypoint.sh

# JCasC location
ENV CASC_JENKINS_CONFIG=/var/jenkins_casc/jenkins.yaml

# Disable setup wizard
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.plugins.git.GitSCM.ALLOW_LOCAL_CHECKOUT=true"

USER jenkins

ENTRYPOINT ["/usr/local/bin/custom-entrypoint.sh"]
