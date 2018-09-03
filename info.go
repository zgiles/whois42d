package main

import (
  "fmt"
  "net/http"
)

func HandleHTTPHelp() http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
      content := `<html><body><pre>
Whois42d JSON API:

Paths:
/               This message, help.
/api/1/text     Query with text response
/api/1/json     Query with json response
/api/1/version  Server version query
/api/1/types    Server types query ( list all schema types )

Query parameter:
The URL variable 'q' should be filled in with your query

Ex:
/api/1/json?q=10.0.0.0/8
/api/1/json?q=SOMEONE-MNT
</pre></body></html>
`
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      w.WriteHeader(http.StatusOK)
      fmt.Fprintln(w, content)
  })
}
