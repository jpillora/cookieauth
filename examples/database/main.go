package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"

	"github.com/jpillora/cookieauth"
)

var db *sql.DB

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
			<link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon">
			<body>hello world</body>
			</html>`))

	})

	var err error

	//Setting up database
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer db.Close()

	_, err = db.Exec(`DROP TABLE IF EXISTS users; CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, pass TEXT)`)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	stmt, err := db.Prepare(`INSERT INTO users(name,pass) VALUES (?,?)`)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec("foo", "bar")
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	_, err = stmt.Exec("baz", "bar")
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	//custom usage
	ca := cookieauth.New()

	ca.SetAuthFunc(dbAuth)

	ca.SetLogger(log.New(os.Stdout, "", log.LstdFlags))
	protected := ca.Wrap(handler)

	log.Print("listening on 8000...")
	log.Fatal(http.ListenAndServe(":8000", protected))
}

func dbAuth(user, pass string) (bool, []byte, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if err != nil {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	stmt, err := db.Prepare("SELECT id FROM users WHERE name = ? AND pass = ?")
	if err != nil {
		return false, nil, err
	}
	defer stmt.Close()

	var userID int
	err = stmt.QueryRow(user, pass).Scan(&userID)
	if err != nil {
		if err != sql.ErrNoRows {
			//DB error
			return false, nil, err
		}
		//No rows is not an error
		return false, nil, nil

	}

	return true, []byte(string(userID) + ":" + user), nil

}
