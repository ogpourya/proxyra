package main

import (
	"os"
	"testing"
)

func TestJSMatcher(t *testing.T) {
	m, err := loadJSMatcher(`function match(url, body, status, headers) { return body.includes("admin"); }`)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.newRunner()
	if err != nil {
		t.Fatal(err)
	}
	if !r.match("http://x/", "hello admin panel", 200, "Content-Type: text/html\n") {
		t.Fatal("want true when body contains admin")
	}
	if r.match("http://x/", "hello user", 200, "Content-Type: text/html\n") {
		t.Fatal("want false when body lacks admin")
	}
	if r.match("http://x/", "admin", 404, "") != true {
		t.Fatal("status/headers must not affect this matcher")
	}

	if _, err := loadJSMatcher(`function nope() { return true; }`); err == nil {
		t.Fatal("want error when match() undefined")
	}
	if _, err := loadJSMatcher(`function match( { broken`); err == nil {
		t.Fatal("want error on syntax error")
	}

	f, _ := os.CreateTemp("", "match*.js")
	f.WriteString(`function match(u, b, s, h) { return s === 200 && h.includes("X-Flag"); }`)
	f.Close()
	defer os.Remove(f.Name())
	mf, err := loadJSMatcher(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	rf, _ := mf.newRunner()
	if !rf.match("http://x/", "anything", 200, "X-Flag: yes\n") {
		t.Fatal("want true from file-based matcher")
	}
	if rf.match("http://x/", "anything", 500, "X-Flag: yes\n") {
		t.Fatal("want false on status mismatch")
	}
}
