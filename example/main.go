package main

import (
	"log"
	"net/http"

	"github.com/jpillora/cookieauth"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world\n"))
	})

	protected := cookieauth.Wrap(handler, "foo", "bar")

	log.Print("listening on 8000...")
	log.Fatal(http.ListenAndServe(":8000", protected))
}
