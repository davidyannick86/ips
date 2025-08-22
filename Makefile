.PHONY: build release clean fast balanced deep aggressive run

# Allow TARGET or IP on the make command line: `make fast TARGET=1.2.3.4` or `make fast IP=1.2.3.4`
TARGET ?= $(IP)

build:
	go build -o nmapgo .
fast:
	@$(MAKE) build
	@if [ -z "$(TARGET)" ]; then echo "Usage: make fast TARGET=<ip_or_host>"; exit 1; fi
	sudo ./nmapgo --profile fast $(TARGET)

balanced:
	@$(MAKE) build
	@if [ -z "$(TARGET)" ]; then echo "Usage: make balanced TARGET=<ip_or_host>"; exit 1; fi
	sudo ./nmapgo --profile balanced $(TARGET)

deep:
	@$(MAKE) build
	@if [ -z "$(TARGET)" ]; then echo "Usage: make deep TARGET=<ip_or_host>"; exit 1; fi
	sudo ./nmapgo --profile deep $(TARGET)

aggressive:
	@$(MAKE) build
	@if [ -z "$(TARGET)" ]; then echo "Usage: make aggressive TARGET=<ip_or_host>"; exit 1; fi
	sudo ./nmapgo --profile aggressive $(TARGET)

run:
	@$(MAKE) build
	@if [ -z "$(PROFILE)" ] || [ -z "$(TARGET)" ]; then echo "Usage: make run PROFILE=<fast|balanced|deep|aggressive> TARGET=<ip_or_host>"; exit 1; fi
	sudo ./nmapgo --profile $(PROFILE) $(TARGET)

clean:
	rm -f nmapgo
	rm -rf release

release:
	mkdir -p release
	ts=$$(date -u +%Y%m%dT%H%MZ)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-darwin-arm64-$$ts .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-linux-amd64-$$ts .
	tar -C release -czf release/nmapgo-darwin-arm64-$$ts.tar.gz nmapgo-darwin-arm64-$$ts
	tar -C release -czf release/nmapgo-linux-amd64-$$ts.tar.gz nmapgo-linux-amd64-$$ts
	sha256sum release/*.tar.gz > release/SHA256SUMS || true
