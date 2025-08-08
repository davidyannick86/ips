package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ip-scanner/internal/web"
)

func main() {
	mux, err := func() (*http.ServeMux, error) {
		srv, err := web.NewServer()
		if err != nil {
			return nil, err
		}
		m := http.NewServeMux()
		m.HandleFunc("/", srv.HomeHandler)
		return m, nil
	}()
	if err != nil {
		log.Fatalf("Erreur init serveur: %v", err)
	}

	addr := ":8080"
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Démarrer le serveur dans une goroutine
	go func() {
		log.Printf("Serveur démarré sur http://localhost%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Erreur serveur: %v", err)
		}
	}()

	// Attendre le signal d'arrêt (Ctrl+C, SIGINT/SIGTERM)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("Arrêt en cours (graceful shutdown)...")

	// Contexte avec timeout pour laisser terminer les requêtes en cours
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Arrêt forcé: %v", err)
	} else {
		log.Println("Serveur arrêté proprement.")
	}
}
