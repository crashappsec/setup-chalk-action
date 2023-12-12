VERSION?=
LOAD?=
DOCKER=docker compose run --rm -T action sh -c

ifneq "$(DEBUG)" ""
ARG_DEBUG=--debug
endif
ifneq "$(COPY)" ""
ARG_COPY_FROM=--copy-from=/chalk/chalk
endif

define SETUP=
set -x && ./setup.sh
endef
define CHECK=
&& which chalk \
&& chalk version \
&& which docker \
&& docker --version
endef

all: default
all: prefix

default:
	$(DOCKER) '\
		$(SETUP) \
		--version=$(VERSION) \
		--load=$(LOAD) \
		$(ARG_DEBUG) \
		$(ARG_COPY_FROM) \
		$(CHECK) \
	'

prefix: USER=runner
prefix:
	$(DOCKER) '\
		$(SETUP) \
		--version=$(VERSION) \
		--load=$(LOAD) \
		--prefix=~/.chalk/bin \
		$(ARG_DEBUG) \
		$(ARG_COPY_FROM) \
		$(CHECK) \
	'

ubuntu alpine:
	TARGET=$@ docker compose build
