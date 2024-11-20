# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

IMAGE_REPOSITORY   := europe-docker.pkg.dev/gardener-project/snapshots/${USER}/falco-event-ingestor
IMAGE_TAG          := $(shell cat VERSION)
COVERPROFILE       := test/output/coverprofile.out
REPO_ROOT          := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR           := $(REPO_ROOT)/hack
VERSION            := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION  := $(VERSION)-$(shell git rev-parse HEAD)
LD_FLAGS           := ""
NAMESPACE          := default

.PHONY: start
start:
	go run \
			cmd/ingestor/main.go \
			--config-file=${CONTROL_KUBECONFIG} \
			--key-file=${CONTROL_KUBECONFIG} \
			--postgress-password-file=${CONTROL_KUBECONFIG} \

.PHONY: deploy
deploy: release
	helm template ingestor chart/ --values chart/values.yaml | kubectl apply -f - -n $(NAMESPACE)

#################################################################
# Rules related to formatting and linting                       #
#################################################################

TOOLS_DIR := hack/tools
include $(TOOLS_DIR)/tools.mk

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT)
	go vet ./...
	GOIMPORTS=$(GOIMPORTS) GOLANGCI_LINT=$(GOLANGCI_LINT) hack/check.sh ./cmd/... ./pkg/...

.PHONY: format
format: $(GOIMPORTS)
	@GOIMPORTS=$(GOIMPORTS) $(REPO_ROOT)/hack/format.sh ./cmd ./pkg

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: build
build:
	@mkdir -p bin
	@go build -o bin/falco-event-ingestor cmd/ingestor/main.go

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: release
release: build docker-image docker-login docker-push

.PHONY: docker-image
docker-image:
	@docker build -t $(IMAGE_REPOSITORY):$(IMAGE_TAG) --rm .

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-push
docker-push:
	@if ! docker images $(IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(IMAGE_TAG); then echo "$(IMAGE_REPOSITORY) version $(IMAGE_TAG) is not yet built. Please run 'make docker-images'"; false; fi
	@gcloud docker -- push $(IMAGE_REPOSITORY):$(IMAGE_TAG)

.PHONY: clean
clean:
	@rm -rf bin/

.PHONY: install
install:
	LD_FLAGS=$(LD_FLAGS) EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) \
	bash $(HACK_DIR)/install.sh ./...

#####################################################################
# Rules for verification, testing and cleaning #
#####################################################################

.PHONY: verify
verify: check format test sast

.PHONY: verify-extended
verify-extended: check format test sast-report

.PHONY: sast
sast: $(GOSEC) ## Run gosec against code
	@./hack/sast.sh

.PHONY: sast-report
sast-report: $(GOSEC) ## Run gosec against code and export report to SARIF.
	@./hack/sast.sh --gosec-report true

.PHONY: test
test:
	@go test ./cmd/... ./pkg/...

.PHONY: test-unit
test-unit:
	@SKIP_INTEGRATION_TESTS=X .ci/test

.PHONY: test-integration
test-integration:
	@SKIP_UNIT_TESTS=X .ci/test

.PHONY: show-coverage
show-coverage:
	@if [ ! -f $(COVERPROFILE) ]; then echo "$(COVERPROFILE) is not yet built. Please run 'COVER=true make test'"; false; fi
	go tool cover -html $(COVERPROFILE)

.PHONY: test-clean
test-clean:
	@find . -name "*.coverprofile" -type f -delete
	@rm -f $(COVERPROFILE)

.PHONY: add-license-headers
add-license-headers: $(GO_ADD_LICENSE)
	@./hack/add_license_headers.sh
