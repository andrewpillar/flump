package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type HashMech uint

type Ref struct {
	Mech HashMech
	Hash []byte
}

type Store interface {
	Put(context.Context, io.Reader) (Object, error)

	Get(Ref) (Object, error)
}

type Object struct {
	io.Reader
	io.Seeker
	io.Closer

	Ref  Ref
	Size int64
	Time time.Time
}

type Filesystem struct {
	dir  string
	mech HashMech
}

//go:generate stringer -type HashMech -linecomment
const (
	MD5    HashMech = iota // md5
	SHA256                 // sha256
)

var (
	mechanismFactories = map[HashMech]func() hash.Hash{
		MD5:    md5.New,
		SHA256: sha256.New,
	}

	ErrUnknownMech = errors.New("unknown hashing mechanism")

	Mechanisms = map[string]HashMech{
		"md5":    MD5,
		"sha256": SHA256,
	}
)

func BaseAddress(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func NewFilesystem(mech HashMech, dir string) (*Filesystem, error) {
	if _, ok := mechanismFactories[mech]; !ok {
		return nil, ErrUnknownMech
	}

	info, err := os.Stat(dir)

	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, errors.New("expected directory for path: " + dir)
	}
	return &Filesystem{
		dir:  dir,
		mech: mech,
	}, nil
}

func ParseRef(s string) (Ref, error) {
	var i int

	for j, r := range s {
		if r == '-' {
			i = j
			break
		}
	}

	bmech := s[:i]
	bhash := s[i+1:]

	var (
		ok  bool
		err error
	)

	ref := Ref{}

	ref.Mech, ok = Mechanisms[string(bmech)]

	if !ok {
		return ref, ErrUnknownMech
	}

	ref.Hash, err = hex.DecodeString(string(bhash))
	return ref, err
}

func (fs *Filesystem) Put(ctx context.Context, r io.Reader) (Object, error) {
	obj := Object{
		Ref: Ref{
			Mech: fs.mech,
		},
	}

	if err := ctx.Err(); err != nil {
		return obj, err
	}

	tmp, err := ioutil.TempFile(fs.dir, "")

	if err != nil {
		return obj, err
	}

	defer os.Remove(tmp.Name())

	hash := mechanismFactories[fs.mech]()

	n, err := io.Copy(io.MultiWriter(hash, tmp), r)

	if err != nil {
		return obj, err
	}

	tmp.Seek(0, io.SeekStart)

	obj.Ref.Hash = hash.Sum(nil)
	obj.Size = n

	refdir := filepath.Join(fs.dir, obj.Ref.Abbrev())

	if err := os.Mkdir(refdir, os.FileMode(0755)); err != nil {
		return obj, err
	}

	dst, err := os.OpenFile(filepath.Join(refdir, obj.Ref.Tail()), os.O_CREATE|os.O_WRONLY, os.FileMode(0600))

	if err != nil {
		return obj, err
	}

	defer dst.Close()

	if _, err := io.Copy(dst, tmp); err != nil {
		return obj, err
	}

	info, err := dst.Stat()

	if err != nil {
		return obj, err
	}

	obj.Time = info.ModTime()
	return obj, nil
}

func (fs *Filesystem) Get(abbrev string) (Object, error) {
	dir := filepath.Join(fs.dir, abbrev)

	info, err := os.Stat(dir)

	if err != nil {
		return Object{}, err
	}

	if !info.IsDir() {
		return Object{}, errors.New("invalid ref")
	}

	var full string

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		parts := strings.Split(path, string(os.PathSeparator))

		full = parts[0] + parts[1]
		return nil
	})

	if err != nil {
		return Object{}, err
	}

	ref, err := ParseRef(full)

	if err != nil {
		return Object{}, err
	}

	obj := Object{
		Ref: ref,
	}

	f, err := os.Open(filepath.Join(dir, ref.Tail()))

	if err != nil {
		return obj, err
	}

	obj.Seeker = f
	obj.Reader = f
	obj.Closer = f
	return obj, nil
}

func (r Ref) Abbrev() string {
	s := r.Mech.String()

	return s + r.String()[len(s):len(s)+8]
}

func (r Ref) Tail() string {
	abbrev := r.Abbrev()
	return r.String()[len(abbrev):]
}

func (r Ref) String() string { return r.Mech.String() + "-" + hex.EncodeToString(r.Hash) }

func serve(srv *http.Server, cert, key string) error {
	if cert != "" && key != "" {
		return srv.ListenAndServeTLS(cert, key)
	}
	return srv.ListenAndServe()
}

func respJSON(w http.ResponseWriter, data interface{}, status int) {
	buf := bytes.Buffer{}

	json.NewEncoder(&buf).Encode(data)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(buf.Len()), 10))
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func handle(secret string, limit int64, fs *Filesystem) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			respJSON(w, map[string]string{"message": "Method not allowed"}, http.StatusMethodNotAllowed)
			return
		}

		if r.Method == "POST" {
			if r.URL.Path != "/" {
				respJSON(w, map[string]string{"message": "Not found"}, http.StatusNotFound)
				return
			}

			if secret != "" {
				val := r.Header.Get("Authorization")

				if val == "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				parts := strings.Split(val, "Bearer ")

				if len(parts) != 2 {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if parts[1] != secret {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			if limit > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}

			obj, err := fs.Put(r.Context(), r.Body)

			if err != nil {
				if strings.Contains(err.Error(), "request body too large") {
					respJSON(w, map[string]string{"message": "Object too big"}, http.StatusBadRequest)
					return
				}

				if strings.Contains(err.Error(), "file exists") {
					respJSON(w, map[string]string{"message": "Object exists"}, http.StatusBadRequest)
					return
				}
				log.Println("ERROR", err)
				respJSON(w, map[string]string{"message": err.Error()}, http.StatusInternalServerError)
				return
			}

			abbrev := obj.Ref.Abbrev()

			data := map[string]interface{}{
				"ref":  abbrev,
				"size": obj.Size,
				"url":  BaseAddress(r) + "/" + abbrev,
			}

			respJSON(w, data, http.StatusCreated)
			return
		}

		trimmed := strings.TrimPrefix(r.URL.Path, "/")
		cleaned := strings.Replace(trimmed, "..", "", -1)

		obj, err := fs.Get(cleaned)

		if err != nil {
			log.Println("ERROR", err)
			respJSON(w, map[string]string{"message": "Not found"}, http.StatusNotFound)
			return
		}

		defer obj.Close()

		http.ServeContent(w, r, "", obj.Time, obj)
	})
}

func main() {
	var (
		addr   string
		mech   string
		dir    string
		key    string
		cert   string
		secret string
		limit  int64
	)

	flag.StringVar(&addr, "addr", ":8080", "the address to serve on")
	flag.StringVar(&mech, "mech", "sha256", "the hashing mechanism to use")
	flag.StringVar(&dir, "dir", ".", "the directory to store the dumped files")
	flag.StringVar(&key, "key", "", "the server key to use for TLS")
	flag.StringVar(&cert, "cert", "", "the server certificate to use for TLS")
	flag.StringVar(&secret, "secret", "", "the secret to use to authenticate requests")
	flag.Int64Var(&limit, "limit", 0, "the maximum file size in bytes that can be uploaded")
	flag.Parse()

	m, ok := Mechanisms[mech]

	if !ok {
		log.Fatalf("unknown hashing mechanism: %s\n", mech)
	}

	fs, err := NewFilesystem(m, dir)

	if err != nil {
		log.Fatalf("failed to initialize directory: %s\n", err)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      handle(secret, limit, fs),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	scheme := "http://"

	if cert != "" && key != "" {
		scheme = "https://"
	}

	host, port, err := net.SplitHostPort(addr)

	if err != nil {
		log.Fatalf("invalid address: %s\n", err)
	}

	if host == "" {
		host, err = os.Hostname()

		if err != nil {
			host = "localhost"
		}
	}

	go func() {
		if err := serve(srv, cert, key); err != nil {
			if err != http.ErrServerClosed {
				log.Println("ERROR", err)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("INFO  ", "serving on", addr)
	log.Println("INFO  ", "flump at:", scheme+host+":"+port)
	log.Println("INFO  ", "using hash mechanism:", mech)
	log.Println("INFO  ", "storing files at:", dir)

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)

	sig := <-c

	srv.Shutdown(ctx)

	log.Println("INFO  ", "received signal", sig, "shutting down")
}
