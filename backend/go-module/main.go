package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type IOCRequest struct {
	IOCs []struct {
		Value string `json:"value"`
		Kind  string `json:"kind"`
	} `json:"iocs"`
}

type Verdict struct {
	IOC      string `json:"ioc"`
	Verdict  string `json:"verdict"`
	Score    int    `json:"score"`
	Source   string `json:"source"`
	Detail   string `json:"detail"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "enrichment_cache.db")
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cache (
		ioc TEXT PRIMARY KEY,
		verdict TEXT,
		score INTEGER,
		source TEXT,
		detail TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func fetchFromCache(ioc string) *Verdict {
	var v Verdict
	var timestamp time.Time
	err := db.QueryRow("SELECT ioc, verdict, score, source, detail, timestamp FROM cache WHERE ioc = ?", ioc).
		Scan(&v.IOC, &v.Verdict, &v.Score, &v.Source, &v.Detail, &timestamp)
	if err != nil {
		return nil
	}
	// Cache valid for 24h
	if time.Since(timestamp) > 24*time.Hour {
		return nil
	}
	return &v
}

func saveToCache(v *Verdict) {
	_, err := db.Exec(`INSERT OR REPLACE INTO cache (ioc, verdict, score, source, detail, timestamp) 
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		v.IOC, v.Verdict, v.Score, v.Source, v.Detail)
	if err != nil {
		log.Printf("Failed to save to cache: %v", err)
	}
}

func mockLookup(ioc, kind string) *Verdict {
	// Simulate network delay of 1-3 seconds
	time.Sleep(time.Duration(rand.Intn(2000)+1000) * time.Millisecond)

	v := &Verdict{
		IOC:    ioc,
		Source: "VirusTotal + AbuseIPDB",
	}

	// Deterministic mock logic based on the string
	if ioc == "45.33.32.156" {
		v.Verdict = "malicious"
		v.Score = 88
		v.Detail = "Reported 847 times for SSH brute force — flagged by 12 vendors."
	} else if kind == "url" && (ioc == "http://bad-actor.org/drop" || ioc == "http://malware.eicar.org/test") {
		v.Verdict = "malicious"
		v.Score = 95
		v.Detail = "Malicious domain — detected by 58 vendors."
	} else if kind == "hash" && ioc == "d41d8cd98f00b204e9800998ecf8427e" {
		v.Verdict = "malicious"
		v.Score = 100
		v.Detail = "Known malware sample (Ransomware) — flagged by 62 vendors."
	} else {
		// Default benign/unknown
		v.Verdict = "benign"
		v.Score = rand.Intn(10)
		v.Detail = "No significant threats detected by vendors."
	}
	return v
}

func enrichHandler(w http.ResponseWriter, r *http.Request) {
	// CORS Headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req IOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results := make([]*Verdict, 0, len(req.IOCs))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, item := range req.IOCs {
		wg.Add(1)
		go func(ioc, kind string) {
			defer wg.Done()
			
			// Check Cache
			if cached := fetchFromCache(ioc); cached != nil {
				mu.Lock()
				results = append(results, cached)
				mu.Unlock()
				return
			}

			// Perform lookup
			v := mockLookup(ioc, kind)
			saveToCache(v)

			mu.Lock()
			results = append(results, v)
			mu.Unlock()
		}(item.Value, item.Kind)
	}

	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": results,
	})
}

func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/enrich", enrichHandler)
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Go Enrichment Service running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
