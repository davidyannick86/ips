# Utiliser l'image officielle Go pour la compilation
FROM golang:1.21-alpine AS builder

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers go.mod et go.sum (si existe)
COPY go.mod ./
COPY go.su[m] ./

# Télécharger les dépendances
RUN go mod download

# Copier le code source
COPY main.go ./

# Compiler l'application pour l'architecture AMD64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o ip-scanner .

# Utiliser une image minimale pour l'exécution
FROM debian:bookworm-slim

# Installer les certificats CA pour les connexions HTTPS
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Créer un utilisateur non-root pour la sécurité
RUN useradd -r -u 1001 -g root appuser

# Définir le répertoire de travail
WORKDIR /app

# Copier l'exécutable depuis l'étape de build
COPY --from=builder /app/ip-scanner .

# Changer la propriété du fichier
RUN chown appuser:root ip-scanner

# Utiliser l'utilisateur non-root
USER appuser

# Exposer le port 8080
EXPOSE 8080

# Définir les labels pour la documentation
LABEL maintainer="Scanner IP Network Tool"
LABEL description="Application Go pour scanner les IP libres du réseau"
LABEL version="1.0"

# Commande par défaut
CMD ["./ip-scanner"]
