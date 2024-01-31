VERSION?=
LOAD?=
DOCKER=docker compose run --rm -T action sh -c

ifneq "$(DEBUG)" ""
ARGS+=--debug
endif
ifneq "$(COPY)" ""
ARGS+=--copy-from=/chalk/chalk
endif
ifneq "$(CHALK_PASSWORD)" ""
ARGS+=--public-key=tests/chalk.pub
ARGS+=--private-key=tests/chalk.key
DEPS+=chalk.key
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

default: $(DEPS)
	$(DOCKER) '\
		$(SETUP) \
		--version=$(VERSION) \
		--load="$(LOAD)" \
		--params='$(subst ",\\\",$(PARAMS))' \
		--token=$(TOKEN) \
		$(ARGS) \
		$(CHECK) \
	'

prefix: USER=runner
prefix: $(DEPS)
	$(DOCKER) '\
		$(SETUP) \
		--version=$(VERSION) \
		--load="$(LOAD)" \
		--params='$(subst ",\\\",$(PARAMS))' \
		--token=$(TOKEN) \
		--prefix=~/.chalk/bin \
		$(ARGS) \
		$(CHECK) \
	'

ubuntu alpine:
	TARGET=$@ docker compose build

chalk.key:
	COSIGN_PASSWORD=$(CHALK_PASSWORD) \
		cosign \
		generate-key-pair \
		--output-key-prefix chalk
	chmod 0644 chalk.key
