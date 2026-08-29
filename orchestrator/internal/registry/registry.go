// Package registry tracks which analyzer service should be called for a
// given (format, language) pair coming out of triage.
package registry

import "sync"

type entry struct {
	name      string
	address   string
	formats   map[string]bool
	languages map[string]bool
}

type Registry struct {
	mu      sync.RWMutex
	entries []entry
}

func New() *Registry {
	return &Registry{}
}

func (r *Registry) Register(name, address string, formats, languages []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry{
		name:      name,
		address:   address,
		formats:   toSet(formats),
		languages: toSet(languages),
	})
}

func (r *Registry) Resolve(format, language string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []string
	for _, e := range r.entries {
		formatOK := e.formats["*"] || e.formats[format]
		langOK := e.languages["*"] || e.languages[language]
		if formatOK && langOK {
			matches = append(matches, e.address)
		}
	}
	return matches
}

// ResolveByName returns the address registered under the given name,
// or "" if not found.
func (r *Registry) ResolveByName(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, e := range r.entries {
		if e.name == name {
			return e.address
		}
	}
	return ""
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
}
