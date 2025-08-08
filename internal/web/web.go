package web

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"ip-scanner/internal/scan"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

type PageData struct {
	Results   []scan.IPResult
	Total     int
	Available int
	ScanTime  string
}

type Server struct {
	tmpl *template.Template
}

func NewServer() (*Server, error) {
	t, err := template.ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}
	return &Server{tmpl: t}, nil
}

func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Début du scan des IP...")
	startTime := time.Now()

	results := scan.ScanIPRange(r.Context())
	scanDuration := time.Since(startTime)

	totalScanned := 244
	freeCount := len(results)

	data := PageData{
		Results:   results,
		Total:     totalScanned,
		Available: freeCount,
		ScanTime:  formatSeconds(scanDuration.Seconds()),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html.tmpl", data); err != nil {
		http.Error(w, "Erreur d'exécution du template", http.StatusInternalServerError)
		return
	}

	log.Printf("Scan terminé: %d IP libres trouvées sur %d scannées (durée: %s)",
		freeCount, totalScanned, formatSeconds(scanDuration.Seconds()))
}

func formatSeconds(s float64) string {
	return fmt.Sprintf("%.2fs", s)
}
