package whois

import (
  "net/http"
  "fmt"
  "bytes"
  "strconv"
  "encoding/json"
)

func (r *Registry) HandleHTTPBoth(t string) http.Handler {
  // t := "json"
  return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
    content := []byte("")
    var m []map[string]string
    q, ok := req.URL.Query()["q"]
    if !ok || len(q[0]) < 1 {
      http.Error(w, "Bad request", 400)
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
      m = append(m,WhoisToMap(c))
      content = append(content[:], c[:]...)
    }
    switch t {
    case "json":
      j, jerr := json.Marshal(m)
      if jerr != nil {
        http.Error(w, "Bad request", 400)
      } else {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        fmt.Fprintln(w, string(j))
      }
      return
    case "text":
      w.Header().Set("Content-Type", "text/plain; charset=utf-8")
      w.WriteHeader(http.StatusOK)
      fmt.Fprintln(w, string(content))
      return
    default:
      fmt.Println(t)
      http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
      return
    }
  })
}

func WhoisToMap(b []byte) map[string]string {
  r := make(map[string]string)
  for _, l := range bytes.Split(b, []byte("\n")) {
    i := bytes.Index(l, []byte(":"))
    if i > 0 {
      r[string(bytes.TrimSpace(l[0:i]))] = string(bytes.TrimSpace(l[i+1:]))
    }
  }
  return r
}

func (r *Registry) HandleHTTPVersion() http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
    m := map[string]string{
      "version": strconv.FormatInt(VERSION, 10),
    }
    j, jerr := json.Marshal(m)
    if jerr != nil {
      http.Error(w, "Bad request", 400)
    } else {
      w.Header().Set("Content-Type", "application/json; charset=utf-8")
      w.WriteHeader(http.StatusOK)
      fmt.Fprintln(w, string(j))
    }
    return
  })
}

func (r *Registry) HandleHTTPTypes() http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request){
    var m []string
    for _, t := range r.whoisTypes {
      m = append(m,t.Name)
    }
    j, jerr := json.Marshal(m)
    if jerr != nil {
      http.Error(w, "Bad request", 400)
    } else {
      w.Header().Set("Content-Type", "application/json; charset=utf-8")
      w.WriteHeader(http.StatusOK)
      fmt.Fprintln(w, string(j))
    }
    return
  })
}
