# Makefile pour le projet Scanner IP

.PHONY: build build-linux clean test run docker-build docker-run deploy help

# Variables
APP_NAME = ip-scanner
BINARY_NAME = $(APP_NAME)
LINUX_BINARY = $(APP_NAME)-linux-amd64

# Aide
help:
	@echo "Commandes disponibles:"
	@echo "  build        - Compiler pour l'OS local"
	@echo "  build-linux  - Compiler pour Linux AMD64"
	@echo "  run          - Lancer l'application localement"
	@echo "  test         - Exécuter les tests"
	@echo "  clean        - Nettoyer les binaires"
	@echo "  docker-build - Construire l'image Docker"
	@echo "  docker-run   - Lancer le container Docker"
	@echo "  deploy       - Déployer sur le serveur (nécessite SERVER=user@ip)"
	@echo ""
	@echo "Exemples:"
	@echo "  make build-linux"
	@echo "  make deploy SERVER=root@192.168.1.100"

# Compilation locale
build:
	go build -o $(BINARY_NAME) ./

# Compilation pour Linux AMD64
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o $(LINUX_BINARY) ./

# Lancer localement
run:
	go run ./

# Tests
test:
	go test -v ./...

# Nettoyer
clean:
	rm -f $(BINARY_NAME) $(LINUX_BINARY)
	docker rmi $(APP_NAME) 2>/dev/null || true

# Docker build
docker-build:
	docker build -t $(APP_NAME) .

# Docker run
docker-run: docker-build
	docker run --rm --network host -p 8080:8080 $(APP_NAME)

# Déploiement (usage: make deploy SERVER=user@server-ip)
deploy:
	@if [ -z "$(SERVER)" ]; then \
		echo "❌ Erreur: Spécifiez le serveur avec SERVER=user@ip"; \
		echo "Exemple: make deploy SERVER=root@192.168.1.100"; \
		exit 1; \
	fi
	./transfer-and-deploy.sh $(SERVER)

# Installation des dépendances
deps:
	go mod tidy
	go mod download
