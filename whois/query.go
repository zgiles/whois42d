package whois

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
)

type pathpair struct {
	objtype string
	obj		string
}

func (r *Registry) handleObject(conn *net.TCPConn, object Object, flags *Flags) bool {
	found := false
	paths := r.findObjectPaths(object)
	for _, p := range paths {
			r.printObject(conn, p.objtype, p.obj)
			found = true
	}
	return found
}

func (r *Registry) findObjectPaths(object Object) []pathpair {
	var paths []pathpair
	for _, t := range r.whoisTypes {
		if t.Kind == ROUTE || t.Kind == ROUTE6 {
			if object[t.Kind] != nil {
				p := r.getObjFromIP(t.Name, object[t.Kind].(net.IP))
				paths = append(paths, p...)
			}
		} else {
			arg := object[t.Kind].(string)
			if t.Pattern.MatchString(arg) {
				paths = append(paths, pathpair{t.Name, arg})
			}
		}
	}
	return paths
}

func (r *Registry) getObjFromIP(objType string, ip net.IP) []pathpair {
	var paths []pathpair
	routePath := path.Join(r.DataPath, objType)
	cidrs, err := readCidrs(routePath)
	if err != nil {
		return paths
	}

	for _, c := range cidrs {
		if c.Contains(ip) {
			obj := strings.Replace(c.String(), "/", "_", -1)
			paths = append(paths, pathpair{objType, obj})
		}
	}
	return paths
}

func (r *Registry) HandleQuery(conn *net.TCPConn) {
	fmt.Fprint(conn, "% " + r.Header + "\n\n")

	query := parseQuery(conn)
	if query == nil {
		return
	}

	flags := query.Flags
	if flags.ServerInfo != "" {
		r.printServerInfo(conn, strings.TrimSpace(flags.ServerInfo))
		return
	}
	found := false
	for _, obj := range query.Objects {
		if r.handleObject(conn, obj, flags) {
			found = true
		}
	}

	if !found {
		fmt.Fprint(conn, "% 404\n")
	}
	fmt.Fprint(conn, "\n")
}

func parseQuery(conn *net.TCPConn) *Query {
	r := bufio.NewReader(conn)
	req, e := r.ReadString('\n')
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", e)
		return nil
	}
	flags, flagSet, err := parseFlags(req)
	if err != nil {
		flagSet.SetOutput(conn)
		if err != flag.ErrHelp {
			fmt.Fprintf(conn, "%s", err)
		}
		flagSet.PrintDefaults()
		return nil
	}

	query := Query{}
	query.Flags = flags
	query.Objects = make([]Object, len(flags.Args))
	for i, arg := range flags.Args {
		query.Objects[i] = parseObject(strings.TrimSpace(arg))
	}
	fmt.Fprintf(os.Stdout, "[%s] %s\n", conn.RemoteAddr(), req)
	return &query
}

func (r *Registry) printServerInfo(conn *net.TCPConn, what string) {
	switch what {
	case "version":
		fmt.Fprintf(conn, "%% whois42d v%d\n", VERSION)
	case "sources":
		fmt.Fprintf(conn, r.RegistryTopLevel+":3:N:0-0\n")
	case "types":
		for _, t := range r.whoisTypes {
			fmt.Fprintf(conn, "%s\n", t.Name)
		}
	default:
		fmt.Fprintf(conn, "%% unknown option %s\n", what)
	}
}

func (r *Registry) printNet(conn *net.TCPConn, name string, ip net.IP) bool {
	routePath := path.Join(r.DataPath, name)
	cidrs, err := readCidrs(routePath)
	if err != nil {
		fmt.Printf("Error reading cidr from '%s'\n", routePath)
	}

	found := false
	for _, c := range cidrs {
		if c.Contains(ip) {
			obj := strings.Replace(c.String(), "/", "_", -1)
			r.printObject(conn, name, obj)
			found = true
		}
	}
	return found
}

func (r *Registry) printObject(conn *net.TCPConn, objType string, obj string) {
	content, path, err := r.retrieveObject(objType, obj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}
	fmt.Fprintf(conn, "%% Information related to '%s':\n", path)
	conn.Write(content)
	fmt.Fprint(conn, "\n")
}
