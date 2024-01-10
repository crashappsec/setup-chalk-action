VERSION?=
LOAD?=
DOCKER=docker compose run --rm -T action sh -c

ifneq "$(DEBUG)" ""
ARGS+=--debug
endif
ifneq "$(COPY)" ""
ARGS+=--copy-from=/chalk/chalk
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
		--params='$(PARAMS)' \
		--token=$(TOKEN) \
		$(ARGS) \
		$(CHECK) \
	'

prefix: USER=runner
prefix:
	$(DOCKER) '\
		$(SETUP) \
		--version=$(VERSION) \
		--load=$(LOAD) \
		--params='$(subst ",\\\",$(PARAMS))' \
		--token=$(TOKEN) \
		--prefix=~/.chalk/bin \
		$(ARGS) \
		$(CHECK) \
	'

ubuntu alpine:
	TARGET=$@ docker compose build
