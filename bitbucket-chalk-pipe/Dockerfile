FROM alpine:3.19

LABEL maintainer="CrashAppSec <support@crashoverride.run>"
LABEL description="Bitbucket Pipe: Install and run Chalk for build artifact observability"

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    coreutils \
    docker-cli

ARG SETUP_SH_REF=main
RUN curl -fsSL \
    "https://raw.githubusercontent.com/crashappsec/setup-chalk-action/${SETUP_SH_REF}/setup.sh" \
    -o /usr/local/bin/chalk-setup.sh && \
    chmod +x /usr/local/bin/chalk-setup.sh

COPY pipe.sh /usr/local/bin/pipe.sh
RUN chmod +x /usr/local/bin/pipe.sh

ENTRYPOINT ["/usr/local/bin/pipe.sh"]
