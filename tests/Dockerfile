ARG BASE

# ----------------------------------------------------------------------------

FROM alpine AS alpine
RUN apk add --no-cache \
    curl \
    sudo

RUN addgroup sudo
RUN adduser runner -D /home/runner -G sudo
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# ----------------------------------------------------------------------------

FROM ubuntu AS ubuntu
RUN apt-get update && \
    apt-get install -y \
        adduser \
        curl \
        sudo \
        && \
    apt-get clean

RUN adduser --home /home/runner --ingroup sudo runner

# ----------------------------------------------------------------------------

FROM fedora AS fedora
RUN yum install \
    curl

RUN groupadd sudo
RUN adduser runner --home-dir /home/runner --groups sudo

# ----------------------------------------------------------------------------

FROM $BASE

RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

ENV PATH=/home/runner/.chalk/bin:$PATH

COPY --from=docker:24 /usr/local/bin/docker /usr/local/bin/docker
