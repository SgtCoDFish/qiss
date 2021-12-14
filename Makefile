SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

VERSION ?= $(shell cat VERSION.txt)

SOURCES=$(shell find . -type f -name "*.go")

# BIN is the directory where tools will be installed
export BIN ?= ${CURDIR}/bin

OS := $(shell go env GOOS)
ARCH := $(shell go env GOARCH)

PKG_CONFIG_PATH=${BIN}

.PHONY: all
all: qiss-client qiss-server

.PHONY: clean
clean:
	@rm -rf $(BIN)

# Run tests
.PHONY: test
test: fmt
	go test ./... -coverprofile bin/cover.out

.PHONY: fmt
fmt:
	@echo "+ $@"
	@if [[ ! -z "$(shell gofmt -l -s . | grep -v vendor | tee /dev/stderr)" ]]; then exit 1; fi

.PHONY: qiss
qiss: qiss-server qiss-client

.PHONY: qiss-server
qiss-server: $(BIN)/qiss-server

.PHONY: qiss-client
qiss-client: $(BIN)/qiss-client

$(BIN)/qiss-server: $(SOURCES) $(BIN)/liboqs/build/compile_commands.json | $(BIN)
	PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) go build -o $@ cmd/qiss-server/main.go

$(BIN)/qiss-client: $(SOURCES) $(BIN)/liboqs/build/compile_commands.json | $(BIN)
	PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) go build -o $@ cmd/qiss-client/main.go

.PHONY: runqiss_server
runqiss_server: $(BIN)/qiss-server
	LD_LIBRARY_PATH=$(BIN)/liboqs/build/lib $<

.PHONY: runqiss_client
runqiss_client: $(BIN)/qiss-client
	LD_LIBRARY_PATH=$(BIN)/liboqs/build/lib $<

${BIN}:
	@mkdir -p ${BIN}

# liboqs

.PHONY: get-liboqs
get-liboqs: compile-liboqs bin/liboqs.pc | $(BIN)
	export PKG_CONFIG_PATH=$(shell pwd)/$(BIN) && go get github.com/open-quantum-safe/liboqs-go/oqs

$(BIN)/liboqs: | $(BIN)
	git clone https://github.com/open-quantum-safe/liboqs $@

$(BIN)/liboqs/build: | $(BIN)/liboqs
	mkdir -p $@

.PHONY: compile-liboqs
compile-liboqs: $(BIN)/liboqs/build/compile_commands.json

# this specific file isn't important, it's just taken as a marker that the lib has been built
$(BIN)/liboqs/build/compile_commands.json: $(BIN)/liboqs/build
	cd $< && cmake -DBUILD_SHARED_LIBS=ON .. && make -j8

bin/liboqs.pc:
	./hack/make_pkgconfig.sh > $@
