package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPResult struct {
	IP        string
	Available bool
	Hostname  string
}

type PageData struct {
	Results   []IPResult
	Total     int
	Available int
	ScanTime  string
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanner d'IP - Réseau Local</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }
        .stat {
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
        }
        .controls {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
        }
        .refresh-btn {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 1.1em;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .refresh-btn:hover {
            transform: translateY(-2px);
        }
        .ip-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            padding: 20px;
        }
        .ip-card {
            border: 2px solid #dee2e6;
            border-radius: 10px;
            padding: 15px;
            transition: all 0.3s ease;
        }
        .ip-card.available {
            border-color: #28a745;
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        }
        .ip-card.unavailable {
            border-color: #dc3545;
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        }
        .ip-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .ip-address {
            font-weight: bold;
            font-size: 1.2em;
            margin-bottom: 8px;
        }
        .ip-status {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-dot.available {
            background: #28a745;
        }
        .status-dot.unavailable {
            background: #dc3545;
        }
        .hostname {
            color: #6c757d;
            font-size: 0.9em;
            font-style: italic;
        }
        .loading {
            text-align: center;
            padding: 50px;
            font-size: 1.2em;
            color: #6c757d;
        }
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            flex-direction: column;
        }
        .spinner {
            width: 50px;
            height: 50px;
            border: 5px solid #f3f3f3;
            border-top: 5px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .loading-text {
            font-size: 1.5em;
            color: #2c3e50;
            font-weight: 500;
        }
        .progress-info {
            margin-top: 15px;
            font-size: 1.1em;
            color: #6c757d;
        }
    </style>
    <script>
        function showLoading() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        }
        
        function refreshScan() {
            showLoading();
            window.location.reload();
        }
        
        // Afficher le message de chargement au démarrage si aucun résultat
        window.addEventListener('load', function() {
            const results = document.querySelectorAll('.ip-card');
            if (results.length === 0) {
                showLoading();
            }
        });
    </script>
</head>
<body>
    <!-- Overlay de chargement -->
    <div id="loadingOverlay" class="loading-overlay" style="display: none;">
        <div class="spinner"></div>
        <div class="loading-text">🔍 Scan en cours...</div>
        <div class="progress-info">Analyse du réseau 192.168.1.2 - 192.168.1.245</div>
    </div>

    <div class="container">
        <div class="header">
            <h1>🌐 Scanner d'IP Libres - Réseau Local</h1>
            <p>Scan du réseau 192.168.1.2 - 192.168.1.245 (IP non utilisées)</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{{.Total}}</div>
                <div class="stat-label">IP scannées</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.Available}}</div>
                <div class="stat-label">IP libres</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.ScanTime}}</div>
                <div class="stat-label">Temps de scan</div>
            </div>
        </div>

        <div class="controls">
            <button class="refresh-btn" onclick="refreshScan()">🔄 Actualiser le scan</button>
        </div>

        <div class="ip-grid">
            {{range .Results}}
            <div class="ip-card available">
                <div class="ip-address">{{.IP}}</div>
                <div class="ip-status">
                    <div class="status-dot available"></div>
                    IP libre (non utilisée)
                </div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>
`

// Fonction de scan ultra-rapide avec test parallèle des ports
func fastPingIP(ip string) bool {
	// Test sur plusieurs ports communs pour une meilleure détection
	ports := []string{"80", "22", "443", "53", "8080", "23", "21", "25"}

	// Canal pour recevoir les résultats
	results := make(chan bool, len(ports))

	// Tester tous les ports en parallèle
	for _, port := range ports {
		go func(p string) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, p), 100*time.Millisecond)
			if err == nil && conn != nil {
				conn.Close()
				results <- true // Service trouvé
				return
			}
			results <- false
		}(port)
	}

	// Attendre les résultats de tous les ports
	for i := 0; i < len(ports); i++ {
		if <-results {
			return true // Au moins un service trouvé = IP utilisée
		}
	}

	return false // Aucun service détecté = IP libre
}

func scanIPRange() []IPResult {
	var results []IPResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Utiliser un canal pour limiter le nombre de goroutines concurrentes
	semaphore := make(chan struct{}, 50) // Limite à 50 goroutines simultanées

	// Scanner de 192.168.1.2 à 192.168.1.245
	for i := 2; i <= 245; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquérir le sémaphore
			defer func() { <-semaphore }() // Libérer le sémaphore

			ip := fmt.Sprintf("192.168.1.%d", i)
			// Utiliser la fonction de scan ultra-rapide
			available := fastPingIP(ip)

			// Pas besoin de résoudre les noms d'hôtes car on ne garde que les IP libres
			mu.Lock()
			results = append(results, IPResult{
				IP:        ip,
				Available: available,
				Hostname:  "", // Pas de résolution DNS pour accélérer
			})
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Filtrer pour ne garder que les IP NON disponibles (qui ne répondent pas)
	var filteredResults []IPResult
	for _, result := range results {
		if !result.Available {
			filteredResults = append(filteredResults, result)
		}
	}

	// Trier les résultats par IP (tri numérique)
	sort.Slice(filteredResults, func(i, j int) bool {
		// Extraire le dernier octet pour un tri numérique correct
		iParts := strings.Split(filteredResults[i].IP, ".")
		jParts := strings.Split(filteredResults[j].IP, ".")

		if len(iParts) == 4 && len(jParts) == 4 {
			iLast, _ := strconv.Atoi(iParts[3])
			jLast, _ := strconv.Atoi(jParts[3])
			return iLast < jLast
		}

		// Fallback sur tri alphabétique
		return filteredResults[i].IP < filteredResults[j].IP
	})

	return filteredResults
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Début du scan des IP...")
	startTime := time.Now()

	results := scanIPRange() // Ne contient que les IP non disponibles
	scanDuration := time.Since(startTime)

	// Calculer le total d'IP scannées (244 IP de 192.168.1.2 à 192.168.1.245)
	totalScanned := 244
	freeCount := len(results) // Nombre d'IP libres (non disponibles)

	data := PageData{
		Results:   results,
		Total:     totalScanned,
		Available: freeCount, // Renommé conceptuellement : nombre d'IP libres
		ScanTime:  fmt.Sprintf("%.2fs", scanDuration.Seconds()),
	}

	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Erreur de template", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Erreur d'exécution du template", http.StatusInternalServerError)
		return
	}

	log.Printf("Scan terminé: %d IP libres trouvées sur %d scannées (durée: %.2fs)",
		freeCount, totalScanned, scanDuration.Seconds())
}

func main() {
	http.HandleFunc("/", homeHandler)

	port := ":8080"
	log.Printf("Serveur démarré sur http://localhost%s", port)
	log.Println("Appuyez sur Ctrl+C pour arrêter le serveur")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Erreur lors du démarrage du serveur:", err)
	}
}
