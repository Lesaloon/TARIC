.PHONY: all build test fmt e2e clean
all: build

build:
	cargo build --workspace
	$(MAKE) -C clients/c

test:
	cargo test --workspace
	$(MAKE) -C clients/c test || true

fmt:
	cargo fmt --all || true
	clang-format -i $(shell find clients/c -type f \( -name '*.c' -o -name '*.h' \)) 2>/dev/null || true
	dotnet format examples/server-csharp/TaricServerDemo || true

e2e:
	$(MAKE) -C tests-e2e run

clean:
	cargo clean
	$(MAKE) -C clients/c clean || true
