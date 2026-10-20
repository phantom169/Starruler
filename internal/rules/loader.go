package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"starruler/internal/baseline"
)

// Store 规则库：target -> Pack。
type Store struct {
	mu    sync.RWMutex
	packs map[string]*baseline.Pack
}

// LoadAuto 优先加载外部磁盘规则目录（允许用户自定义修改），
// 目录不存在时回退到内嵌规则（单二进制免依赖运行）。
func LoadAuto(dir string, embedded fs.FS) (*Store, error) {
	if st, err := LoadDir(dir); err == nil {
		return st, nil
	}
	return LoadFS(embedded)
}

// LoadFS 从内嵌文件系统加载（子树根为 rules/）。
func LoadFS(fsys fs.FS) (*Store, error) {
	st := &Store{packs: map[string]*baseline.Pack{}}
	entries, err := fs.ReadDir(fsys, "rules")
	if err != nil {
		return nil, fmt.Errorf("读取内嵌规则: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join("rules", e.Name()))
		if err != nil {
			return nil, err
		}
		if err := st.parse(e.Name(), b); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func LoadDir(dir string) (*Store, error) {
	st := &Store{packs: map[string]*baseline.Pack{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取规则目录 %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if err := st.parse(e.Name(), b); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func (s *Store) parse(name string, b []byte) error {
	var p baseline.Pack
	if err := yaml.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("解析规则 %s: %w", name, err)
	}
	if p.Target == "" || len(p.Items) == 0 {
		return nil
	}
	if p.Collector == "" {
		p.Collector = p.Target
	}
	s.packs[p.Target] = &p
	return nil
}

func (s *Store) Get(target string) (*baseline.Pack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.packs[target]
	return p, ok
}

func (s *Store) All() []*baseline.Pack {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*baseline.Pack, 0, len(s.packs))
	for _, p := range s.packs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.packs)
}

// ItemCount 自动核查条目总数。
func (s *Store) ItemCount() int {
	n := 0
	for _, p := range s.All() {
		n += len(p.Items)
	}
	return n
}
