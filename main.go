package main

import (
	"encoding/json"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	addr        = ":8080"
	dbFile      = "urls.db"
	letters     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	codeLength  = 6
	sessionName = "usession"
	sessionKey  = "super-secret-key" // change in production!
)

var (
	tpl   *template.Template
	store = sessions.NewCookieStore([]byte(sessionKey))
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
	rand.Seed(time.Now().UnixNano())
}

func main() {
	// 1. Open the database
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	log.Printf("Opened DB at %s", dbFile)

	// 2. Ensure schema
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT UNIQUE NOT NULL,
            original TEXT NOT NULL,
            custom_alias BOOLEAN NOT NULL DEFAULT 0,
            expires_at TIMESTAMP,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            click_count INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );`,
		`CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER NOT NULL,
            clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            referrer TEXT,
            FOREIGN KEY(url_id) REFERENCES urls(id)
        );`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			log.Fatalf("failed to exec schema stmt: %v", err)
		}
	}

	// 3. List existing tables
	rows, err := db.Query(`
        SELECT name FROM sqlite_master
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
    `)
	if err != nil {
		log.Fatalf("failed to list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatalf("scan failed: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	log.Printf("Existing tables: %v", tables)

	// 4. Inspect `urls` schema
	if contains(tables, "urls") {
		rows, err = db.Query(`PRAGMA table_info(urls)`)
		if err != nil {
			log.Fatalf("failed to inspect urls schema: %v", err)
		}
		log.Println("urls schema:")
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, dfltValue, pk interface{}
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
				log.Fatalf("scan schema failed: %v", err)
			}
			log.Printf("  %-15s %s", name, ctype)
		}
		rows.Close()
	}

	// 5. Router & handlers
	r := mux.NewRouter()

	// Public
	r.HandleFunc("/", requireNoAuth(indexHandler)).Methods("GET")
	r.HandleFunc("/signup", signupHandler(db)).Methods("POST")
	r.HandleFunc("/login", loginHandler(db)).Methods("POST")

	// Authenticated
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/dashboard", requireAuth(dashboardHandler(db))).Methods("GET")
	r.HandleFunc("/shorten", requireAuth(shortenHandler(db))).Methods("POST")
	r.HandleFunc("/delete/{id}", requireAuth(deleteHandler(db))).Methods("POST")

	// Redirect
	r.HandleFunc("/r/{code}", redirectHandler(db)).Methods("GET")

	// Static assets
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

// contains checks for a string in a slice.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// Middleware

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, sessionName)
		if sess.Values["user_id"] == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func requireNoAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, sessionName)
		if sess.Values["user_id"] != nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// Handlers

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	tpl.ExecuteTemplate(w, "index.html", nil)
}

func signupHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if len(user) < 3 || len(pass) < 6 {
			http.Error(w, "invalid username/password", http.StatusBadRequest)
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if _, err := db.Exec("INSERT INTO users(username,password_hash) VALUES(?,?)", user, string(hash)); err != nil {
			http.Error(w, "user exists", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		var id int
		var hash string
		if err := db.QueryRow("SELECT id,password_hash FROM users WHERE username=?", user).Scan(&id, &hash); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		sess, _ := store.Get(r, sessionName)
		sess.Values["user_id"] = id
		sess.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, sessionName)
	delete(sess.Values, "user_id")
	sess.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func dashboardHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, sessionName)
		raw := sess.Values["user_id"]

		// safe conversion
		var uid int
		switch v := raw.(type) {
		case int:
			uid = v
		case float64:
			uid = int(v)
		default:
			log.Printf("bad user_id type: %T\n", raw)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		rows, err := db.Query(`
            SELECT id, code, original, custom_alias, expires_at, click_count, created
            FROM urls
            WHERE user_id=?
            ORDER BY created DESC
        `, uid)
		if err != nil {
			log.Printf("dashboard: db query failed for user_id=%d: %T – %v\n", uid, err, err)
			http.Error(w, "DB Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type Link struct {
			ID          int
			Code        string
			Original    string
			CustomAlias bool
			ExpiresAt   sql.NullTime
			ClickCount  int
			Created     time.Time
		}
		var links []Link
		for rows.Next() {
			var l Link
			if err := rows.Scan(
				&l.ID, &l.Code, &l.Original, &l.CustomAlias,
				&l.ExpiresAt, &l.ClickCount, &l.Created,
			); err != nil {
				log.Printf("dashboard: row scan failed: %v\n", err)
				continue
			}
			links = append(links, l)
		}
		if err := rows.Err(); err != nil {
			log.Printf("dashboard: rows iteration error: %v\n", err)
		}

		data := struct {
			Links []Link
			Host  string
		}{links, r.Host}

		if err := tpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
			log.Printf("dashboard: template execution failed: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func shortenHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, sessionName)
		raw := sess.Values["user_id"]
		// safe conversion
		var uid int
		switch v := raw.(type) {
		case int:
			uid = v
		case float64:
			uid = int(v)
		default:
			http.Error(w, "invalid session", http.StatusUnauthorized)
			return
		}

		orig := strings.TrimSpace(r.FormValue("url"))
		alias := strings.TrimSpace(r.FormValue("alias"))
		expStr := r.FormValue("expires")

		u, err := url.ParseRequestURI(orig)
		if err != nil {
			http.Error(w, "invalid URL", http.StatusBadRequest)
			return
		}

		var exp sql.NullTime
		if expStr != "" {
			t, err := time.Parse("2006-01-02", expStr)
			if err != nil {
				http.Error(w, "invalid date", http.StatusBadRequest)
				return
			}
			exp = sql.NullTime{Time: t, Valid: true}
		}

		code := alias
		custom := false
		if code == "" {
			for {
				code = randString(codeLength)
				var cnt int
				db.QueryRow("SELECT COUNT(1) FROM urls WHERE code=?", code).Scan(&cnt)
				if cnt == 0 {
					break
				}
			}
		} else {
			var cnt int
			db.QueryRow("SELECT COUNT(1) FROM urls WHERE code=?", code).Scan(&cnt)
			if cnt > 0 {
				http.Error(w, "alias in use", http.StatusBadRequest)
				return
			}
			custom = true
		}

		if _, err := db.Exec(`
            INSERT INTO urls(user_id,code,original,custom_alias,expires_at)
            VALUES(?,?,?,?,?)
        `, uid, code, u.String(), custom, exp); err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}

		// ✅ AJAX response handling here
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "application/json") || r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			w.Header().Set("Content-Type", "application/json")
			shortURL := fmt.Sprintf("http://%s/r/%s", r.Host, code)
			json.NewEncoder(w).Encode(map[string]string{
				"short_url": shortURL,
			})
			return
		}

		// Fallback: normal redirect if not AJAX
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}


func deleteHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(mux.Vars(r)["id"])
		db.Exec("DELETE FROM urls WHERE id=?", id)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func redirectHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := mux.Vars(r)["code"]
		var (
			id        int
			orig      string
			expiresAt sql.NullTime
		)
		err := db.QueryRow(`
            SELECT id, original, expires_at
            FROM urls WHERE code=?
        `, code).Scan(&id, &orig, &expiresAt)
		if err != nil || (expiresAt.Valid && time.Now().After(expiresAt.Time)) {
			http.NotFound(w, r)
			return
		}

		// record click
		db.Exec("UPDATE urls SET click_count = click_count + 1 WHERE id=?", id)
		ref := r.Referer()
		db.Exec("INSERT INTO clicks(url_id,referrer) VALUES(?,?)", id, ref)

		http.Redirect(w, r, orig, http.StatusFound)
	}
}

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}