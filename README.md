# URL Shortener in Go
A fully functional **URL shortener** built from scratch using **Golang** and **SQLite**. Users can sign up, log in, shorten URLs (with optional custom aliases and expiry dates), and track click analytics. Ideal for learning full-stack backend development and showcasing skills in building real-world web applications.

---

## ✨ Features

- 🔐 **User Authentication**
  - Signup, login, logout using hashed passwords (bcrypt)
  - Session management via secure cookies

- 🔗 **Shorten URLs**
  - Random short codes (e.g. `abc123`)
  - Optional custom alias (`/r/my-link`)
  - Optional expiry date

- 📊 **Analytics**
  - Tracks click counts
  - Stores referrers
  - Dashboard view for all user links

- 📁 **Frontend**
  - Simple HTML-based templates using `html/template`
  - No frontend frameworks—fully Go-powered

- 🧱 **Database**
  - Lightweight SQLite backend
  - Three tables: `users`, `urls`, `clicks`

---

## 🛠️ Tech Stack

- **Language**: Go (Golang)
- **Database**: SQLite (`github.com/mattn/go-sqlite3`)
- **Router**: Gorilla Mux
- **Templates**: `html/template`
- **Session Handling**: Gorilla Sessions

---

## 🚀 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/PepeTheBuilder74/go-url-shortener.git
cd go-url-shortener
2. Install Go dependencies
bash
Copy
Edit
go mod tidy
3. Run the server
bash
Copy
Edit
go run main.go
The server will start on: http://localhost:8080

📂 Folder Structure
php
Copy
Edit
.
├── main.go           # Entry point with full server code
├── urls.db           # SQLite DB file (auto-created on first run)
├── templates/        # HTML templates
│   ├── index.html
│   ├── dashboard.html
├── static/           # CSS or assets (optional)
├── go.mod
├── .gitignore
└── README.md
✅ Usage Demo
Visit http://localhost:8080

Sign up / Log in

Shorten a link with optional custom alias and expiry

Share the shortened link: http://localhost:8080/r/abc123

Track clicks in your dashboard

🧪 Sample Data (For Testing)
Try shortening:

https://example.com

https://youtube.com

Try setting:

Custom alias: myyt

Expiry: 2025-12-31

🔒 Security Notes
Passwords are hashed using bcrypt

Sessions use secure cookies (Gorilla Sessions)

SQL queries are parameterized (to avoid SQL injection)

🧠 Future Improvements (Ideas)
Rate limiting or abuse prevention

Email verification

API support (REST or gRPC)

Deployment to cloud (Render, Railway, etc.)

UI improvements using Go templating or React

🤝 License
MIT License. Feel free to fork, modify, and use this project for learning or personal projects.

👨‍💻 Author
Made with ❤️ by PepeTheBuilder74
Link : https://go-url-shortener-4k1r.onrender.com/dashboard
