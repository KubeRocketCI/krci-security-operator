# VERSION defines the project version used to tag the manager image by default.
VERSION ?= 0.1.0

# Image URL to use all building/pushing image targets
IMG ?= docker.io/epamedp/krci-security-operator:$(VERSION)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run the unit tests and, when helm is installed, the chart render tests.
	go test -race ./... -coverprofile cover.out

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

.PHONY: helm-docs
helm-docs: helmdocs ## Generate deploy-templates/README.md from README.md.gotmpl.
	"$(HELMDOCS)"

.PHONY: validate-docs
validate-docs: helm-docs ## Fail if the generated chart docs are out of date.
	@git diff -s --exit-code deploy-templates/README.md || (echo "Run 'make helm-docs' to address the issue." && git diff && exit 1)

.PHONY: changelog
changelog: git-chglog ## Generate CHANGELOG.md.
ifneq (${NEXT_RELEASE_TAG},)
	"$(GITCHGLOG)" --next-tag v${NEXT_RELEASE_TAG} -o CHANGELOG.md
else
	"$(GITCHGLOG)" -o CHANGELOG.md
endif

##@ Build

# The binary is a container artifact, so GOOS defaults to linux regardless of
# the host (use `make run` to execute locally). GOARCH is overridable so CI
# can produce both architectures for multi-arch image builds:
#   GOARCH=amd64 make build && GOARCH=arm64 make build
# The Dockerfile only copies dist/manager-${TARGETARCH}; it compiles nothing.
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)

.PHONY: build
build: fmt vet ## Build manager binary into dist/manager-$(GOARCH).
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o dist/manager-$(GOARCH) cmd/main.go

.PHONY: clean
clean:  ## clean up
	-rm -rf dist
	-rm -f cover.out

.PHONY: run
run: fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: build ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# The Dockerfile copies prebuilt dist/manager-<arch> binaries, so every listed
# platform needs a matching `GOARCH=<arch> make build` prerequisite below.
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	GOARCH=amd64 $(MAKE) build
	GOARCH=arm64 $(MAKE) build
	- $(CONTAINER_TOOL) buildx create --name krci-security-operator-builder
	$(CONTAINER_TOOL) buildx use krci-security-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} .
	- $(CONTAINER_TOOL) buildx rm krci-security-operator-builder

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
HELMDOCS ?= $(LOCALBIN)/helm-docs
GITCHGLOG ?= $(LOCALBIN)/git-chglog

## Tool Versions
HELMDOCS_VERSION ?= v1.14.2
GITCHGLOG_VERSION ?= v0.15.4
GOLANGCI_LINT_VERSION ?= v2.15.0

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: helmdocs
helmdocs: $(HELMDOCS) ## Download helm-docs locally if necessary.
$(HELMDOCS): $(LOCALBIN)
	$(call go-install-tool,$(HELMDOCS),github.com/norwoodj/helm-docs/cmd/helm-docs,$(HELMDOCS_VERSION))

.PHONY: git-chglog
git-chglog: $(GITCHGLOG) ## Download git-chglog locally if necessary.
$(GITCHGLOG): $(LOCALBIN)
	$(call go-install-tool,$(GITCHGLOG),github.com/git-chglog/git-chglog/cmd/git-chglog,$(GITCHGLOG_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef
