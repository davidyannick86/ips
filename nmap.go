package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	nmap "github.com/Ullaakut/nmap/v2"
)

// ScanResult représente le résultat pour une cible
type ScanResult struct {
	Target    string
	Output    string
	Free      bool
	Err       error
	Duration  time.Duration
	OpenPorts []string
	OSGuess   string
}

func main() {
	workers := flag.Int("workers", max(2, runtime.NumCPU()/2), "Nombre de scans concurrents")
	listFile := flag.String("file", "", "Fichier contenant une cible par ligne")
	outDir := flag.String("out", "scans", "Répertoire de sortie des rapports")
	ports := flag.String("ports", "-p-", "Spécification des ports (ex: -p-, -p 1-1024, -F)")
	extra := flag.String("extra", "--version-all --reason", "Options nmap supplémentaires (ignorées si --profile utilisé)")
	noA := flag.Bool("noA", false, "Ne pas utiliser -A (pour aller plus vite)")
	quiet := flag.Bool("quiet", false, "Mode silencieux: n'affiche que le résumé final")
	timeout := flag.Duration("timeout", 0, "Timeout par hôte (ex: 5m). 0 = illimité")
	profile := flag.String("profile", "", "Profil de scan prédéfini: fast | balanced | deep | aggressive")
	progress := flag.Bool("progress", true, "Afficher progression / ETA")
	udpTop := flag.Int("udp-top", 0, "Top N ports UDP en plus (UDP scan)")
	precheck := flag.Bool("precheck", false, "Ping scan avant pour filtrer les hôtes down")
	jsonOut := flag.String("json", "", "Fichier JSON récapitulatif")
	csvOut := flag.String("csv", "", "Fichier CSV récapitulatif")
	noLog := flag.Bool("no-log", false, "Ne pas écrire les fichiers de résultats (scans/*.txt, JSON)")
	clean := flag.Bool("clean", false, "Vider le répertoire de sortie avant le run")
	singleLog := flag.Bool("single-log", false, "Écrire un seul fichier de log au lieu de fichiers par cible")
	singleLogFile := flag.String("single-log-file", "scan.log", "Nom du fichier unique si --single-log")
	noEmoji := flag.Bool("no-emoji", false, "Désactiver les émojis")
	flag.Parse()

	targets, err := collectTargets(*listFile, flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erreur collecte cibles:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <cible1> <cible2>...\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Pour certains types de scan (SYN) les privilèges root aident – on ré-exec en sudo si pas root.
	if os.Geteuid() != 0 {
		fmt.Println("Élévation privilèges (sudo)...")
		args := append([]string{"-k", os.Args[0]}, os.Args[1:]...)
		if err := syscall.Exec("/usr/bin/sudo", args, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, "Echec sudo:", err)
			os.Exit(1)
		}
		return
	}

	if !*noLog {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "Erreur création dossier:", err)
			os.Exit(1)
		}
		if *clean {
			if err := cleanOutDir(*outDir); err != nil {
				fmt.Fprintln(os.Stderr, "Erreur lors du nettoyage de out:", err)
				os.Exit(1)
			}
		}
	}

	// Profils
	if *profile != "" {
		switch strings.ToLower(*profile) {
		case "fast":
			*ports = "-F"
			*extra = "--reason"
			*noA = true
			if *timeout == 0 {
				*timeout = 30 * time.Second
			}
		case "balanced":
			*ports = "-p 1-1024"
			*extra = "--reason"
			if *timeout == 0 {
				*timeout = 2 * time.Minute
			}
		case "deep":
			// valeurs par défaut
		case "aggressive":
			*ports = "-F"
			*extra = "--reason"
			*noA = true
			if *timeout == 0 {
				*timeout = 20 * time.Second
			}
			if *udpTop == 0 {
				*udpTop = 20
			}
		default:
			fmt.Fprintf(os.Stderr, "Profil inconnu: %s\n", *profile)
			os.Exit(1)
		}
	}

	if len(targets) < *workers {
		*workers = len(targets)
		if *workers == 0 {
			*workers = 1
		}
	}

	useEmoji := !*noEmoji
	if !*quiet {
		fmt.Printf("%s Démarrage (%d cibles, %d workers) profil=%s\n", pick(useEmoji, "🚀", ""), len(targets), *workers, valueOr(*profile, "custom"))
		fmt.Printf("%s Args: ports='%s' extra='%s' -A=%v udp-top=%d timeout=%v precheck=%v json=%s\n", pick(useEmoji, "🧩", ""), *ports, *extra, !*noA, *udpTop, *timeout, *precheck, valueOr(*jsonOut, "-"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n" + pick(useEmoji, "⚠️ ", "") + "Interruption -> arrêt...")
		cancel()
	}()

	if *precheck {
		alive := preCheckHosts(ctx, targets)
		if !*quiet {
			fmt.Printf("%s Précheck: %d/%d vivants\n", pick(useEmoji, "🔍", ""), len(alive), len(targets))
		}
		if len(alive) == 0 {
			fmt.Println("Aucun hôte vivant")
			return
		}
		targets = alive
	}

	jobCh := make(chan string)
	resCh := make(chan ScanResult)
	var wg sync.WaitGroup

	// Prépare le fichier unique si demandé
	var singleF *os.File
	if *singleLog && !*noLog {
		p := filepath.Join(*outDir, *singleLogFile)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Impossible d'ouvrir le fichier unique de log:", err)
			os.Exit(1)
		}
		singleF = f
		defer singleF.Close()
	}

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobCh {
				if ctx.Err() != nil {
					return
				}
				start := time.Now()
				r := runScan(ctx, t, *ports, *extra, !*noA, *timeout, *udpTop)
				r.Duration = time.Since(start)
				resCh <- r
			}
		}()
	}

	go func() {
		for _, t := range targets {
			jobCh <- t
		}
		close(jobCh)
		wg.Wait()
		close(resCh)
	}()

	var freeCnt, upCnt, failCnt int64
	var total int64
	var sumDur int64
	doneCh := make(chan struct{})

	if *progress && !*quiet {
		go func() {
			tick := time.NewTicker(1 * time.Second)
			defer tick.Stop()
			start := time.Now()
			for {
				select {
				case <-tick.C:
					done := atomic.LoadInt64(&total)
					if done == 0 {
						fmt.Printf("%s Progress: 0/%d elapsed=%s \r", pick(useEmoji, "⏳", ""), len(targets), time.Since(start).Truncate(time.Second))
						continue
					}
					avg := time.Duration(atomic.LoadInt64(&sumDur) / done)
					rem := len(targets) - int(done)
					eta := time.Duration(0)
					if rem > 0 {
						eta = avg * time.Duration(rem)
					}
					fmt.Printf("%s Progress: %d/%d up=%d free=%d fail=%d avg=%ss ETA=%s \r", pick(useEmoji, "⏳", ""), done, len(targets), atomic.LoadInt64(&upCnt), atomic.LoadInt64(&freeCnt), atomic.LoadInt64(&failCnt), durToSecStr(avg), eta.Truncate(time.Second))
				case <-doneCh:
					return
				}
			}
		}()
	}

	results := make([]ScanResult, 0, len(targets))
	for r := range resCh {
		atomic.AddInt64(&total, 1)
		atomic.AddInt64(&sumDur, r.Duration.Nanoseconds())
		base := sanitizeFilename(r.Target)
		if r.Err != nil && !errors.Is(r.Err, context.Canceled) {
			atomic.AddInt64(&failCnt, 1)
			if !*noLog {
				if singleF != nil {
					_, _ = singleF.WriteString("== FAIL: " + r.Target + " ==\n" + r.Output + "\nERR: " + r.Err.Error() + "\n\n")
				} else {
					writeFileSafe(*outDir, base+".error.txt", r.Output+"\nERR: "+r.Err.Error())
				}
			}
			if !*quiet && !*progress {
				fmt.Printf("%s [FAIL] %s (%v)\n", pick(useEmoji, "❌", ""), r.Target, r.Err)
			}
		} else if r.Free {
			atomic.AddInt64(&freeCnt, 1)
			if !*noLog {
				if singleF != nil {
					_, _ = singleF.WriteString("== FREE: " + r.Target + " ==\n" + r.Output + "\n\n")
				} else {
					writeFileSafe(*outDir, base+".free.txt", r.Output)
				}
			}
			if !*quiet && !*progress {
				fmt.Printf("%s [FREE] %s (%.0fs)\n", pick(useEmoji, "🟢", ""), r.Target, r.Duration.Seconds())
			}
		} else {
			atomic.AddInt64(&upCnt, 1)
			if !*noLog {
				if singleF != nil {
					_, _ = singleF.WriteString("== UP: " + r.Target + " ==\n" + r.Output + "\n\n")
				} else {
					writeFileSafe(*outDir, base+".txt", r.Output)
				}
			}
			if !*quiet && !*progress {
				fmt.Printf("%s [UP]   %s (%.0fs)\n", pick(useEmoji, "🔓", ""), r.Target, r.Duration.Seconds())
			}
		}
		results = append(results, r)
	}
	close(doneCh)

	done := atomic.LoadInt64(&total)
	avg := time.Duration(0)
	if done > 0 {
		avg = time.Duration(atomic.LoadInt64(&sumDur) / done)
	}
	if *progress && !*quiet {
		fmt.Print(strings.Repeat(" ", 140) + "\r")
	}
	outLabel := *outDir
	if *noLog {
		outLabel = "(logs disabled)"
	}
	fmt.Printf("%s Résumé: total=%d up=%d free=%d failed=%d avg=%.2fs -> %s\n", pick(useEmoji, "📊", ""), done, atomic.LoadInt64(&upCnt), atomic.LoadInt64(&freeCnt), atomic.LoadInt64(&failCnt), avg.Seconds(), outLabel)
	if *jsonOut != "" {
		if *noLog {
			if !*quiet {
				fmt.Printf("%s JSON suppressed because --no-log is set\n", pick(useEmoji, "📝", ""))
			}
		} else {
			writeJSON(*jsonOut, results)
			if !*quiet {
				fmt.Printf("%s JSON: %s\n", pick(useEmoji, "📝", ""), *jsonOut)
			}
		}
	}

	if *csvOut != "" {
		if *noLog {
			if !*quiet {
				fmt.Printf("%s CSV suppressed because --no-log is set\n", pick(useEmoji, "📄", ""))
			}
		} else {
			writeCSV(*csvOut, results)
			if !*quiet {
				fmt.Printf("%s CSV: %s\n", pick(useEmoji, "📄", ""), *csvOut)
			}
		}
	}

	if !*quiet {
		fmt.Printf("\n%s Détails:\n", pick(useEmoji, "🔎", ""))
		for _, r := range results {
			status := "occupée"
			icon := pick(useEmoji, "🔓", "UP")
			if r.Free {
				status = "libre"
				icon = pick(useEmoji, "🟢", "FREE")
			}
			if r.Err != nil {
				status = "erreur"
				icon = pick(useEmoji, "❌", "ERR")
			}
			osPart := ""
			if r.OSGuess != "" {
				osPart = " | OS: " + r.OSGuess
			}
			fmt.Printf("%s %s -> %s | ports:%d%s | %.2fs\n", icon, r.Target, status, len(r.OpenPorts), osPart, r.Duration.Seconds())
		}
	}
}

// collectTargets lit un fichier et combine avec les args CLI
func collectTargets(file string, args []string) ([]string, error) {
	set := make(map[string]struct{})
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		set[s] = struct{}{}
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	for _, a := range args {
		add(a)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out, nil
}

// runScan exécute un scan pour une cible unique.
func runScan(parent context.Context, target, ports, extra string, useA bool, perHostTimeout time.Duration, udpTop int) ScanResult {
	ctx := parent
	if perHostTimeout > 0 {
		c2, cancel := context.WithTimeout(parent, perHostTimeout)
		defer cancel()
		ctx = c2
	}

	scanner, err := buildScanner(target, ports, extra, useA, udpTop)
	if err != nil {
		return ScanResult{Target: target, Free: true, Err: err}
	}

	type rstruct struct {
		run      *nmap.Run
		warnings []string
		err      error
	}
	ch := make(chan rstruct, 1)
	go func() { run, warnings, err := scanner.Run(); ch <- rstruct{run, warnings, err} }()

	var run *nmap.Run
	var warnings []string
	select {
	case <-ctx.Done():
		return ScanResult{Target: target, Free: true, Err: ctx.Err(), Output: "timeout ou annulé"}
	case r := <-ch:
		run, warnings, err = r.run, r.warnings, r.err
	}

	combined := buildRawFromResult(run, warnings)
	if err != nil {
		free := (run != nil && len(run.Hosts) == 0)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("timeout (%s)", perHostTimeout)
		}
		return ScanResult{Target: target, Output: combined, Free: free, Err: err}
	}
	openPorts, osGuess, free := extractHosts(run)
	return ScanResult{Target: target, Output: combined, Free: free, OpenPorts: openPorts, OSGuess: osGuess}
}

func buildScanner(target, ports, extra string, useA bool, udpTop int) (*nmap.Scanner, error) {
	opts := []nmap.Option{nmap.WithTargets(target)}
	// Ports / modes
	if strings.Contains(ports, "-F") {
		opts = append(opts, nmap.WithFastMode())
	} else if strings.Contains(ports, "-p") {
		spec := strings.TrimSpace(strings.TrimPrefix(ports, "-p"))
		spec = strings.Trim(spec, " :")
		if spec == "-" || spec == "" {
			opts = append(opts, nmap.WithPorts("1-65535"))
		} else {
			opts = append(opts, nmap.WithPorts(spec))
		}
	}
	// La lib ne fournit pas d'option directe "--top-ports N".
	// On active un UDP scan simple; pour limiter on reste en fast mode si demandé.
	if udpTop > 0 {
		opts = append(opts, nmap.WithUDPScan())
	}
	if useA {
		opts = append(opts, nmap.WithOSDetection(), nmap.WithServiceInfo(), nmap.WithVersionAll(), nmap.WithDefaultScript())
	} else {
		if strings.Contains(extra, "--version-all") {
			opts = append(opts, nmap.WithVersionAll(), nmap.WithServiceInfo())
		}
	}
	if strings.Contains(extra, "--reason") {
		opts = append(opts, nmap.WithReason())
	}
	if os.Geteuid() == 0 {
		opts = append(opts, nmap.WithSYNScan())
	}
	return nmap.NewScanner(opts...)
}

func extractHosts(run *nmap.Run) (ports []string, osGuess string, free bool) {
	free = true
	if run == nil {
		return
	}
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			if strings.EqualFold(p.State.State, "open") {
				ports = append(ports, fmt.Sprintf("%d/%s", p.ID, strings.ToLower(p.Protocol)))
				free = false
			}
		}
		if len(h.OS.Matches) > 0 && osGuess == "" {
			osGuess = h.OS.Matches[0].Name
		}
	}
	return
}

func buildRawFromResult(res *nmap.Run, warnings []string) string {
	if res == nil {
		return strings.Join(warnings, "\n")
	}
	var b strings.Builder
	if len(warnings) > 0 {
		b.WriteString("Warnings:\n")
		for _, w := range warnings {
			b.WriteString(" - " + w + "\n")
		}
	}
	for _, h := range res.Hosts {
		b.WriteString("Host: ")
		for _, a := range h.Addresses {
			b.WriteString(a.Addr + " ")
		}
		b.WriteString("\n")
		for _, p := range h.Ports {
			b.WriteString(fmt.Sprintf(" %d/%s %s %s\n", p.ID, p.Protocol, p.State.State, p.Service.Name))
		}
		if len(h.OS.Matches) > 0 {
			b.WriteString(" OS: " + h.OS.Matches[0].Name + "\n")
		}
	}
	return b.String()
}

func writeFileSafe(dir, name, content string) {
	_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

func sanitizeFilename(s string) string {
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}
	return strings.Map(repl, s)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func valueOr(s, fb string) string {
	if s == "" {
		return fb
	}
	return s
}
func pick(enabled bool, a, b string) string {
	if enabled {
		return a
	}
	return b
}
func durToSecStr(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	if d.Seconds() < 1 {
		return fmt.Sprintf("%.2f", d.Seconds())
	}
	return fmt.Sprintf("%.1f", d.Seconds())
}

// cleanOutDir supprime les fichiers réguliers dans le répertoire donné (ne supprime pas le répertoire lui-même)
func cleanOutDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() {
			_ = os.Remove(p)
		}
	}
	return nil
}

// preCheckHosts: utilise un Ping Scan unique (plus rapide que spawn  N fois) et filtre les hôtes up.
func preCheckHosts(ctx context.Context, targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	scanner, err := nmap.NewScanner(nmap.WithPingScan(), nmap.WithTargets(targets...))
	if err != nil {
		return targets
	} // fallback
	type rstruct struct {
		run      *nmap.Run
		warnings []string
		err      error
	}
	ch := make(chan rstruct, 1)
	go func() { run, w, err := scanner.Run(); ch <- rstruct{run, w, err} }()
	var run *nmap.Run
	select {
	case <-ctx.Done():
		return targets
	case r := <-ch:
		run = r.run
	}
	alive := []string{}
	if run != nil {
		for _, h := range run.Hosts {
			if len(h.Addresses) > 0 && h.Status.State == "up" {
				alive = append(alive, h.Addresses[0].Addr)
			}
		}
	}
	if len(alive) == 0 {
		return alive
	}
	return alive
}

func writeJSON(path string, results []ScanResult) {
	type J struct {
		Target    string   `json:"target"`
		Free      bool     `json:"free"`
		Error     string   `json:"error,omitempty"`
		Duration  float64  `json:"duration_sec"`
		OpenPorts []string `json:"open_ports,omitempty"`
		PortCount int      `json:"port_count"`
		OS        string   `json:"os,omitempty"`
	}
	arr := make([]J, 0, len(results))
	for _, r := range results {
		j := J{Target: r.Target, Free: r.Free, Duration: r.Duration.Seconds(), OpenPorts: r.OpenPorts, PortCount: len(r.OpenPorts), OS: r.OSGuess}
		if r.Err != nil {
			j.Error = r.Err.Error()
		}
		arr = append(arr, j)
	}
	b, _ := json.MarshalIndent(arr, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

// writeCSV exporte un récapitulatif simple en CSV
func writeCSV(path string, results []ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	// En-tête
	_, _ = f.WriteString("target,free,error,duration_sec,port_count,open_ports,os\n")
	for _, r := range results {
		errStr := ""
		if r.Err != nil {
			// Remplacer nouvelles lignes et virgules
			errStr = strings.ReplaceAll(strings.ReplaceAll(r.Err.Error(), "\n", " "), ",", " ")
		}
		open := strings.Join(r.OpenPorts, "|")
		// Échapper potentiels caractères CSV basiques en entourant de guillemets si besoin
		if strings.ContainsAny(open, ",\n\" ") {
			open = "\"" + strings.ReplaceAll(open, "\"", "'") + "\""
		}
		osGuess := r.OSGuess
		if strings.ContainsAny(osGuess, ",\n\"") {
			osGuess = "\"" + strings.ReplaceAll(osGuess, "\"", "'") + "\""
		}
		line := fmt.Sprintf("%s,%t,%s,%.2f,%d,%s,%s\n", r.Target, r.Free, errStr, r.Duration.Seconds(), len(r.OpenPorts), open, osGuess)
		_, _ = f.WriteString(line)
	}
}
