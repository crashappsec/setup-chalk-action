# ----------------------------------------------------------------------------

FROM alpine as alpine

RUN apk add --no-cache \
    curl \
    sudo

RUN addgroup sudo
RUN adduser runner -D /home/runner -G sudo
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

ENV PATH=/home/runner/.chalk/bin:$PATH

COPY --from=docker:24 /usr/local/bin/docker /usr/local/bin/docker

# ----------------------------------------------------------------------------

FROM ubuntu as ubuntu

RUN apt-get update && \
    apt-get install -y \
        curl \
        wget \
        sudo \
        && \
    apt-get clean

RUN adduser --home /home/runner --ingroup sudo runner
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

ENV PATH=/home/runner/.chalk/bin:$PATH

COPY --from=docker:24 /usr/local/bin/docker /usr/local/bin/docker
