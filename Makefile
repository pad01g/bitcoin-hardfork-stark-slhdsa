# All tooling runs inside Docker (linux/amd64 image with Rust + RISC Zero).
# Nothing is installed on the host.

IMAGE      ?= bhss-dev:latest
PLATFORM   ?= linux/amd64
CARGO_VOL  ?= bhss-cargo-registry
TARGET_VOL ?= bhss-target
RISC0_VOL  ?= bhss-risc0-cache
WORKDIR    := /work
# The RISC Zero C++ kernels need several GB per compiler process; keep
# parallelism low so an 8 GB Docker VM does not OOM-kill the build.
JOBS       ?= 1
# RISC Zero's generated C++ prover kernels (several 7 MB sources) need >4 GB
# per compiler at -O3; -O1 fits in a shared 8 GB VM (slower proving, same
# results). Override with RISC0_CXXFLAGS=-O3 on a big machine.
RISC0_CXXFLAGS ?= -O1
# zkVM segment size (power of two). 2^17 keeps the CPU prover under ~1.6 GB;
# 2^19 was OOM-killed in a shared 8 GB VM.
SEGMENT_PO2 ?= 17

DOCKER_RUN = docker run --rm --platform $(PLATFORM) \
	-v "$(CURDIR):$(WORKDIR)" \
	-v $(CARGO_VOL):/usr/local/cargo/registry \
	-v $(TARGET_VOL):$(WORKDIR)/target \
	-v $(RISC0_VOL):/root/.cache \
	-e CARGO_TARGET_DIR=$(WORKDIR)/target \
	-e CARGO_BUILD_JOBS=$(JOBS) \
	-e CXXFLAGS="$(RISC0_CXXFLAGS)" \
	-e SEGMENT_PO2=$(SEGMENT_PO2) \
	-e RUST_LOG=$${RUST_LOG:-info} \
	-w $(WORKDIR) $(DOCKER_RUN_EXTRA) $(IMAGE)

.PHONY: image build test check clippy prove e2e e2e-real shell clean-volumes bins

image:            ## Build the dev image (Rust 1.88 + rzup + RISC Zero 3.0.6)
	docker build --platform $(PLATFORM) -t $(IMAGE) -f docker/Dockerfile docker

build:            ## cargo build --release (guest programs are built by build.rs)
	$(DOCKER_RUN) cargo build --release --workspace

bins: build       ## Copy release binaries out of the target volume into ./bin
	mkdir -p bin
	$(DOCKER_RUN) sh -c 'cp target/release/bhssd target/release/bhss-cli target/release/bhss-snapshot /work/bin/'

check:
	$(DOCKER_RUN) cargo check --workspace --all-targets

clippy:
	$(DOCKER_RUN) cargo clippy --workspace --all-targets -- -D warnings

test:             ## Unit + integration tests (RISC Zero dev-mode, seconds)
	$(DOCKER_RUN) cargo test --release --workspace --no-fail-fast

prove:            ## Produce and verify a REAL STARK for a small block (CPU; minutes)
	$(DOCKER_RUN) cargo test --release -p bhss-prover --features real-proof-tests -- --nocapture real_block_proof

e2e: bins         ## Multi-node regtest end-to-end test (dev-mode proofs)
	PROVE_MODE=dev SEGMENT_PO2=$(SEGMENT_PO2) tests/e2e.sh

e2e-real: bins    ## End-to-end with real STARKs for every block (slow)
	PROVE_MODE=real SEGMENT_PO2=$(SEGMENT_PO2) tests/e2e.sh

shell:            ## Interactive shell in the dev image
	docker run --rm -it --platform $(PLATFORM) -v "$(CURDIR):$(WORKDIR)" -v $(CARGO_VOL):/usr/local/cargo/registry -v $(TARGET_VOL):$(WORKDIR)/target -v $(RISC0_VOL):/root/.cache -w $(WORKDIR) $(IMAGE) bash

clean-volumes:
	docker volume rm -f $(CARGO_VOL) $(TARGET_VOL) $(RISC0_VOL)
