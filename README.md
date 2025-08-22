# nmapgo

Scanner réseau concurrent en Go basé sur la librairie [`github.com/Ullaakut/nmap/v2`](https://github.com/Ullaakut/nmap) offrant profils prêts à l'emploi, progression temps réel, pré‑filtrage (ping scan) et export JSON enrichi.

## Caractéristiques

- Ré-exécution automatique via `sudo` pour profiter des scans SYN / OS detection
- Pool de workers (`--workers`) pour paralléliser les cibles
- Profils prêts: `fast`, `balanced`, `deep`, `aggressive`
- Personnalisation: `--ports`, `--extra`, `--noA`, `--udp-top`
- Pré‑filtrage rapide avec ping scan (`--precheck`)
- Scan UDP (activation simple) si `--udp-top N` (>0) – limitation: la lib ne gère pas encore le vrai `--top-ports N` interne; l'argument active un scan UDP générique
- Progression + ETA (`--progress=false` pour désactiver)
- Timeout par cible (`--timeout 45s`, etc.)
- Export JSON détaillé (`--json out.json`) avec ports, OS, durée, erreurs
- Export CSV (`--csv out.csv`) condensé
- Fichiers individuels dans `scans/` (`.txt`, `.free.txt`, `.error.txt`)
- Émojis optionnels (`--no-emoji` pour désactiver)
- Implémentation pure Go (pas de parsing fragile d'un binaire externe, hors élévation)

## Installation

```bash
go build -o nmapgo .
```

Note: le binaire généré par `go build` peut être nommé comme tu veux. Le dépôt utilise le nom `nmapgo` pour le binaire ; tu peux lancer :

```bash
./nmapgo --help
# ou (privilèges root pour certains scans)
sudo ./nmapgo --profile fast 192.168.1.10
```

Alternative rapide (Makefile)

```makefile
# build binaire local
build:
  go build -o nmapgo .

# build releases multiplateformes (darwin arm64 + linux amd64)
release:
  mkdir -p release
  ts=$$(date -u +%Y%m%dT%H%MZ)
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-darwin-arm64-$$ts .
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-linux-amd64-$$ts .
  tar -C release -czf release/nmapgo-darwin-arm64-$$ts.tar.gz nmapgo-darwin-arm64-$$ts
  tar -C release -czf release/nmapgo-linux-amd64-$$ts.tar.gz nmapgo-linux-amd64-$$ts
```

## Release

Les artefacts de release sont placés dans `release/` (binaries et archives `.tar.gz`). Exemple rapide pour générer et vérifier une release :

```bash
cd /path/to/repo
mkdir -p release
ts=$(date -u +%Y%m%dT%H%MZ)

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-darwin-arm64-${ts} .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -trimpath -o release/nmapgo-linux-amd64-${ts} .
tar -C release -czf release/nmapgo-darwin-arm64-${ts}.tar.gz nmapgo-darwin-arm64-${ts}
tar -C release -czf release/nmapgo-linux-amd64-${ts}.tar.gz nmapgo-linux-amd64-${ts}

# (optionnel) checksums
sha256sum release/*.tar.gz > release/SHA256SUMS
```

Si tu souhaites distribuer un binaire mac directement dans la racine du dépôt (utile pour tests rapides), copie simplement l'artefact `release/nmapgo-darwin-arm64-*` vers `./nmapgo`, rends‑le exécutable et lance :

```bash
cp release/nmapgo-darwin-arm64-20250822T1533Z ./nmapgo
chmod +x ./nmapgo
sudo ./nmapgo --profile fast 192.168.1.43
```

Si tu veux conserver un nom alternatif, crée un lien symbolique vers `nmapgo` :

```bash
ln -sf ./nmapgo ./nmap-alias
```

## Usage de base

```bash
sudo ./nmapgo 192.168.1.10 192.168.1.11
```

## Profils

| Profil     | Ports            | Options ajoutées            | -A par défaut | Timeout | Notes                                                   |
| ---------- | ---------------- | --------------------------- | ------------- | ------- | ------------------------------------------------------- |
| fast       | -F (top 100 TCP) | --reason                    | Non           | 30s     | Dégrossissage rapide                                    |
| balanced   | 1-1024 TCP       | --reason                    | Oui           | 2m      | Compromis vitesse / info                                |
| deep       | 1-65535 TCP      | --version-all --reason      | Oui           | (none)  | Large spectre (long)                                    |
| aggressive | -F TCP + UDP opt | --reason (+ UDP si demandé) | Non           | 20s     | Rapide, peut manquer services (faux négatifs possibles) |

Remarque: `--udp-top N` active un scan UDP (pas de sélection exacte des *top N* ports faute d'option dédiée dans la lib, N est traité comme simple déclencheur).

## Exemples

```bash
# Scan rapide (top 100 ports TCP) + progression
sudo ./nmapgo --profile fast 192.168.1.43

# Balanced sur liste de cibles + export JSON
sudo ./nmapgo --profile balanced --file hosts.txt --json res.json --csv res.csv

# Scan agressif + activation UDP + précheck
sudo ./nmapgo --profile aggressive --udp-top 30 --precheck 10.0.0.1 10.0.0.2

# Scan personnalisé 1-1024 sans -A avec timeout 45s
sudo ./nmapgo --ports "-p 1-1024" --noA --timeout 45s 192.168.1.50

# Désactiver la barre de progression (logs ligne par ligne)
sudo ./nmapgo --profile fast --progress=false 192.168.1.60

# Ne pas écrire de fichiers de résultats (utile pour test rapide)
sudo ./nmapgo --no-log --profile fast 192.168.1.60

# Vider le dossier de sortie avant le run
sudo ./nmapgo --clean --profile balanced --file hosts.txt

# Écrire un seul fichier de log (append) au lieu d'un fichier par cible
sudo ./nmapgo --single-log --single-log-file all-scans.log --profile deep 192.168.1.0/24
```

## Export JSON

Structure (un objet par cible):

```json
[
  {
    "target": "192.168.1.43",
    "free": false,
    "error": "",
    "duration_sec": 12.34,
    "open_ports": ["22/tcp", "80/tcp"],
    "port_count": 2,
    "os": "Linux 5.X"
  }
]
```
