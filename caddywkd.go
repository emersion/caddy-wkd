package caddywkd

import (
	"net/http"
	"os"

	"github.com/emersion/go-openpgp-wkd"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"golang.org/x/crypto/openpgp"
)

func init() {
	caddy.RegisterPlugin("wkd", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type plugin struct {
	Next    httpserver.Handler
	Pubkeys map[string]openpgp.EntityList
	Handler wkd.Handler
}

func (p *plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !httpserver.Path(r.URL.Path).Matches(wkd.Base) {
		return p.Next.ServeHTTP(w, r)
	}

	p.Handler.ServeHTTP(w, r)
	return 0, nil
}

func (p *plugin) Discover(hash string) ([]*openpgp.Entity, error) {
	pubkey, ok := p.Pubkeys[hash]
	if !ok {
		return nil, wkd.ErrNotFound
	}
	return pubkey, nil
}

func setup(c *caddy.Controller) error {
	pubkeys := map[string]openpgp.EntityList{}
	for c.Next() {
		if !c.NextArg() {
			return c.ArgErr()
		}

		path := c.Val()
		f, err := os.Open(path)
		if err != nil {
			return err
		}

		el, err := openpgp.ReadKeyRing(f)
		f.Close()
		if err != nil {
			return err
		}

		for _, e := range el {
			for _, ident := range e.Identities {
				// TODO: check domain part of the address
				hash, err := wkd.HashAddress(ident.UserId.Email)
				if err != nil {
					return err
				}

				pubkeys[hash] = append(pubkeys[hash], e)
			}
		}
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		p := &plugin{Pubkeys: pubkeys, Next: next}
		p.Handler.Discover = p.Discover
		return p
	})

	return nil
}
