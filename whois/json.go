package whois

import (
  "net/http"
  "fmt"
)

func (r *Registry) HandleHTTPJSON(w http.ResponseWriter, req *http.Request) {
    content := []byte("")
    q, ok := req.URL.Query()["q"]
    if !ok || len(q[0]) < 1 {
      http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
      return
    }
    o := parseObject(q[0])
    paths := r.findObjectPaths(o)
    for _, p := range paths {
      c, _, err := r.retrieveObject(p.objtype, p.obj)
      if err != nil {
        http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
        return
      }
      content = append(content[:], c[:]...)
    }
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, string(content))
}
