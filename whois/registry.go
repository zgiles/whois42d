package whois

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

type Registry struct {
	DataPath         string
	Header           string
	DNSTopLevel      string
	RegistryTopLevel string
	whoisTypes       []Type
}

type Type struct {
	Name    string
	Pattern *regexp.Regexp
	Kind    int
}

type Object map[int]interface{}

const (
	UPPER = iota
	LOWER
	ROUTE
	ROUTE6
)

type Query struct {
	Objects []Object
	Flags   *Flags
}

func New(DataPath string, Header string, DNSTopLevel string, RegistryTopLevel string) Registry {
	r := Registry{DataPath: DataPath, Header: Header, DNSTopLevel: DNSTopLevel, RegistryTopLevel: RegistryTopLevel}
	r.whoisTypes = []Type{
		{"aut-num", regexp.MustCompile(`^AS([0123456789]+)$`), UPPER},
		{"dns", regexp.MustCompile(`.` + r.DNSTopLevel + `$`), LOWER},
		{"person", regexp.MustCompile(`-` + r.RegistryTopLevel + `$`), UPPER},
		{"mntner", regexp.MustCompile(`-MNT$`), UPPER},
		{"schema", regexp.MustCompile(`-SCHEMA$`), UPPER},
		{"organisation", regexp.MustCompile(`ORG-`), UPPER},
		{"tinc-keyset", regexp.MustCompile(`^SET-.+-TINC$`), UPPER},
		{"tinc-key", regexp.MustCompile(`-TINC$`), UPPER},
		{"as-set", regexp.MustCompile(`^AS`), UPPER},
		{"route-set", regexp.MustCompile(`^RS-`), UPPER},
		{"inetnum", nil, ROUTE},
		{"inet6num", nil, ROUTE6},
		{"route", nil, ROUTE},
		{"route6", nil, ROUTE6},
		{"as-block", regexp.MustCompile(`\d+_\d+`), UPPER},
	}
	return r
}

func (r *Registry) retrieveObject(objType string, obj string) ([]byte, string, error) {
	file := path.Join(r.DataPath, objType, obj)
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return []byte(""), string(""), err
	}
	fall, fallerr := ioutil.ReadAll(f)
	if fallerr != nil {
		return []byte(""), string(""), err
	}
	return fall, file[len(r.DataPath)+1:], nil
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

func readCidrs(path string) ([]net.IPNet, error) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	cidrs := []net.IPNet{}
	for _, f := range files {
		name := strings.Replace(f.Name(), "_", "/", -1)
		_, cidr, err := net.ParseCIDR(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip invalid net '%s'", f.Name())
			continue
		}
		i := sort.Search(len(cidrs), func(i int) bool {
			c := cidrs[i]
			return bytes.Compare(c.Mask, cidr.Mask) >= 0
		})

		if i < len(cidrs) {
			cidrs = append(cidrs[:i], append([]net.IPNet{*cidr}, cidrs[i:]...)...)
		} else {
			cidrs = append(cidrs, *cidr)
		}
	}

	return cidrs, nil
}

func parseObject(arg string) Object {
	obj := path.Base(arg)
	object := Object{
		UPPER: strings.ToUpper(obj),
		LOWER: strings.ToLower(obj),
	}

	ip := net.ParseIP(obj)
	if ip == nil {
		ip, _, _ = net.ParseCIDR(arg)
	}
	if ip != nil {
		if ip.To4() == nil {
			object[ROUTE6] = ip
		} else {
			object[ROUTE] = ip.To4()
		}
	}
	return object
}
