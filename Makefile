BUILD_DIR ?= build
BUILD_TYPE ?= Debug
CMAKE_GENERATOR ?=
IMAGE_REPO ?= harbor.peinser.com/uas/quic-sni-router
QSR_VERSION ?= $(shell awk '/VERSION/ && /quic-sni-router/ { print $$3; exit }' CMakeLists.txt)
IMAGE_TAG ?= $(QSR_VERSION)-$(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
QSR_CPU_TARGET ?=
QSR_ENABLE_LTO ?= OFF
DOCKER ?= docker
CLANG ?= clang

.PHONY: help configure build format lint test test-e2e test-e2e-reload fuzz-smoke sanitize benchmark benchmark-native docker-build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

configure: ## Configure CMake build
	@if [ -f "$(BUILD_DIR)/CMakeCache.txt" ] && ! grep -q "^CMAKE_HOME_DIRECTORY:INTERNAL=$$(pwd)$$" "$(BUILD_DIR)/CMakeCache.txt"; then \
		echo "Removing stale CMake cache in $(BUILD_DIR)"; \
		cmake -E rm -rf "$(BUILD_DIR)"; \
	fi
	cmake -S . -B $(BUILD_DIR) $(if $(CMAKE_GENERATOR),-G $(CMAKE_GENERATOR),) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DQSR_CPU_TARGET=$(QSR_CPU_TARGET) -DQSR_ENABLE_LTO=$(QSR_ENABLE_LTO)

build: configure ## Build router and tests
	cmake --build $(BUILD_DIR)

format: ## Format C sources
	clang-format -i include/qsr/*.h src/*.c tests/unit/*.c tests/fuzz/*.c tests/bench/*.c

lint: configure ## Run static checks available on the host
	@if command -v clang-tidy >/dev/null 2>&1; then \
		clang-tidy -p $(BUILD_DIR) src/*.c tests/unit/*.c; \
	else \
		echo "clang-tidy unavailable; run lint in the devcontainer or CI"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then exit 1; fi; \
	fi
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,style,performance,portability --error-exitcode=1 --std=c11 --inline-suppr -Iinclude src tests; \
	else \
		echo "cppcheck unavailable; run lint in the devcontainer or CI"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then exit 1; fi; \
	fi

test: build ## Run unit tests
	ctest --test-dir $(BUILD_DIR) --output-on-failure

test-e2e: ## Run Docker HTTP/3 end-to-end test
	tests/e2e/http3/run.sh

test-e2e-reload: ## Run Docker hot-reload end-to-end test
	tests/e2e/reload/run.sh

fuzz-smoke: ## Build fuzzers and run a short smoke test
	@if ! printf '%s\n' 'int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { (void)data; (void)size; return 0; }' | $(CLANG) -fsanitize=fuzzer -x c - -o /tmp/qsr-fuzzer-check >/dev/null 2>&1; then \
		echo "libFuzzer runtime is unavailable for $(CLANG); run this target in the devcontainer or CI"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then exit 1; fi; \
	else \
		if [ -f "$(BUILD_DIR)-fuzz/CMakeCache.txt" ] && ! grep -q "^CMAKE_HOME_DIRECTORY:INTERNAL=$$(pwd)$$" "$(BUILD_DIR)-fuzz/CMakeCache.txt"; then \
			echo "Removing stale CMake cache in $(BUILD_DIR)-fuzz"; \
			cmake -E rm -rf "$(BUILD_DIR)-fuzz"; \
		fi; \
		cmake -S . -B $(BUILD_DIR)-fuzz $(if $(CMAKE_GENERATOR),-G $(CMAKE_GENERATOR),) -DCMAKE_BUILD_TYPE=Debug -DQSR_BUILD_FUZZERS=ON -DCMAKE_C_COMPILER=$(CLANG); \
		cmake --build $(BUILD_DIR)-fuzz; \
		$(BUILD_DIR)-fuzz/fuzz_quic_initial -runs=100; \
		$(BUILD_DIR)-fuzz/fuzz_quic_frames -runs=100; \
		$(BUILD_DIR)-fuzz/fuzz_tls_client_hello -runs=100; \
	fi

sanitize: ## Run unit tests under ASAN/UBSAN
	@if [ -f "$(BUILD_DIR)-sanitize/CMakeCache.txt" ] && ! grep -q "^CMAKE_HOME_DIRECTORY:INTERNAL=$$(pwd)$$" "$(BUILD_DIR)-sanitize/CMakeCache.txt"; then \
		echo "Removing stale CMake cache in $(BUILD_DIR)-sanitize"; \
		cmake -E rm -rf "$(BUILD_DIR)-sanitize"; \
	fi
	cmake -S . -B $(BUILD_DIR)-sanitize $(if $(CMAKE_GENERATOR),-G $(CMAKE_GENERATOR),) -DCMAKE_BUILD_TYPE=Debug -DQSR_ENABLE_SANITIZERS=ON -DCMAKE_C_COMPILER=$(CLANG)
	cmake --build $(BUILD_DIR)-sanitize
	ctest --test-dir $(BUILD_DIR)-sanitize --output-on-failure

benchmark: ## Run synthetic dataplane benchmarks
	@if [ -f "$(BUILD_DIR)-bench/CMakeCache.txt" ] && ! grep -q "^CMAKE_HOME_DIRECTORY:INTERNAL=$$(pwd)$$" "$(BUILD_DIR)-bench/CMakeCache.txt"; then \
		echo "Removing stale CMake cache in $(BUILD_DIR)-bench"; \
		cmake -E rm -rf "$(BUILD_DIR)-bench"; \
	fi
	cmake -S . -B $(BUILD_DIR)-bench $(if $(CMAKE_GENERATOR),-G $(CMAKE_GENERATOR),) -DCMAKE_BUILD_TYPE=Release -DQSR_BUILD_BENCHMARKS=ON -DQSR_CPU_TARGET=$(QSR_CPU_TARGET) -DQSR_ENABLE_LTO=$(QSR_ENABLE_LTO)
	cmake --build $(BUILD_DIR)-bench
	$(BUILD_DIR)-bench/bench_dataplane

benchmark-native: ## Run benchmarks with host CPU tuning and LTO
	$(MAKE) benchmark QSR_CPU_TARGET=native QSR_ENABLE_LTO=ON BUILD_DIR=$(BUILD_DIR)-native

docker-build: ## Build production container image
	$(DOCKER) build \
		--build-arg VERSION=$(IMAGE_TAG) \
		--build-arg REVISION=$$(git rev-parse HEAD 2>/dev/null || echo unknown) \
		--build-arg CREATED=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		--build-arg QSR_CPU_TARGET=$(QSR_CPU_TARGET) \
		--build-arg QSR_ENABLE_LTO=$(QSR_ENABLE_LTO) \
		-f docker/Dockerfile \
		-t $(IMAGE_REPO):$(IMAGE_TAG) .

clean: ## Remove build outputs
	rm -rf $(BUILD_DIR) $(BUILD_DIR)-fuzz $(BUILD_DIR)-sanitize $(BUILD_DIR)-bench ${BUILD_DIR}-native ${BUILD_DIR}-devcontainer ${BUILD_DIR}-devcontainer-fuzz ${BUILD_DIR}-devcontainer-sanitize ${BUILD_DIR}-devcontainer-test ${BUILD_DIR}-native-bench ${BUILD_DIR}-native-check
