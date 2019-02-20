package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jpillora/cookieauth"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
			<link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon">
			<body>hello world</body>
			</html>`))
	})

	//custom usage
	ca := cookieauth.New()

	//Custom Auth Function, in this case it grants access if the username contains more than 3 "4"
	authFunc := func(user, pass string) (bool, []byte, error) {
		if strings.Count(user, "4") > 3 {
			return true, []byte(user), nil
		}
		return false, nil, nil

	}
	ca.SetAuthFunc(authFunc)

	ca.SetLogger(log.New(os.Stdout, "", log.LstdFlags))
	protected := ca.Wrap(handler)

	log.Print("listening on 8000...")
	log.Fatal(http.ListenAndServe(":8000", protected))
}
