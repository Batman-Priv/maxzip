
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Batman-Priv/maxzip/internal/ui"
)

type FileRef struct {
	Abs     string 
	Rel     string 
	Size    int64
	Mode    os.FileMode 
	ModTime time.Time   

	IsSymlink  bool   
	LinkTarget string 
}

func CollectFiles(root string, excludes []string) ([]FileRef, []string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, err
	}

	if !info.IsDir() {
		fr, ok, err := statEntry(root, filepath.Base(root), info)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, nil
		}
		return []FileRef{fr}, nil, nil
	}

	var entries []FileRef
	var allDirs []string
	hasFile := map[string]bool{}

	err = filepath.Walk(root, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if fi.IsDir() {
			allDirs = append(allDirs, rel)
			return nil
		}

		for _, pat := range excludes {
			if ok, _ := filepath.Match(pat, filepath.Base(path)); ok {
				return nil
			}
		}

		fr, ok, err := statEntry(path, rel, fi)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		entries = append(entries, fr)

		for dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." && dir != "/" && dir != ""; dir = filepath.ToSlash(filepath.Dir(dir)) {
			hasFile[dir] = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	var emptyDirs []string
	for _, d := range allDirs {
		if !hasFile[d] {
			emptyDirs = append(emptyDirs, d)
		}
	}
	return entries, emptyDirs, nil
}

func statEntry(path, rel string, fi os.FileInfo) (FileRef, bool, error) {
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Warn(fmt.Sprintf("warning: skipping unreadable symlink: %s", path)))
			return FileRef{}, false, nil
		}
		return FileRef{
			Abs: path, Rel: rel, Mode: fi.Mode(), ModTime: fi.ModTime(),
			IsSymlink: true, LinkTarget: target,
		}, true, nil
	}
	if !fi.Mode().IsRegular() {
		return FileRef{}, false, nil
	}
	return FileRef{Abs: path, Rel: rel, Size: fi.Size(), Mode: fi.Mode(), ModTime: fi.ModTime()}, true, nil
}

type resolvedInput struct {
	path    string
	abs     string
	isDir   bool
	isLink  bool
	target  string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func resolveInputs(inputs []string) ([]resolvedInput, error) {
	var out []resolvedInput
	for _, spec := range inputs {
		matches := []string{spec}
		if hasGlobMeta(spec) {
			m, err := filepath.Glob(spec)
			if err != nil {
				return nil, fmt.Errorf("invalid pattern %q: %w", spec, err)
			}
			if len(m) == 0 {
				return nil, fmt.Errorf("no files match pattern %q", spec)
			}
			matches = m
		}

		for _, m := range matches {
			info, err := os.Lstat(m)
			if err != nil {
				return nil, err
			}
			abs, err := filepath.Abs(m)
			if err != nil {
				return nil, err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, terr := os.Readlink(m)
				if terr != nil {
					fmt.Fprintln(os.Stderr, ui.Warn(fmt.Sprintf("warning: skipping unreadable symlink: %s", m)))
					continue
				}
				out = append(out, resolvedInput{
					path: m, abs: abs, isLink: true, target: target,
					mode: info.Mode(), modTime: info.ModTime(),
				})
				continue
			}
			if info.IsDir() {
				out = append(out, resolvedInput{path: m, abs: abs, isDir: true})
				continue
			}
			if !info.Mode().IsRegular() {
				continue
			}
			out = append(out, resolvedInput{
				path: m, abs: abs, isDir: false,
				size: info.Size(), mode: info.Mode(), modTime: info.ModTime(),
			})
		}
	}
	return out, nil
}

func CollectFilesMulti(inputs []string, excludes []string) ([]FileRef, []string, error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("no input specified")
	}

	resolved, err := resolveInputs(inputs)
	if err != nil {
		return nil, nil, err
	}
	if len(resolved) == 0 {
		return nil, nil, fmt.Errorf("no files found")
	}

	single := len(resolved) == 1 && resolved[0].isDir

	var all []FileRef
	var emptyDirs []string
	seen := map[string]bool{}
	seenDir := map[string]bool{}

	addUnique := func(fr FileRef) {
		name := fr.Rel
		if seen[name] {
			ext := filepath.Ext(name)
			stem := strings.TrimSuffix(name, ext)
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s_%d%s", stem, i, ext)
				if !seen[candidate] {
					name = candidate
					break
				}
			}
		}
		seen[name] = true
		fr.Rel = name
		all = append(all, fr)
	}

	for _, r := range resolved {
		if r.isDir {
			files, dirs, err := CollectFiles(r.path, excludes)
			if err != nil {
				return nil, nil, err
			}
			prefix := filepath.Base(r.path)
			for _, fr := range files {
				if !single {
					fr.Rel = filepath.ToSlash(filepath.Join(prefix, fr.Rel))
				}
				addUnique(fr)
			}
			for _, d := range dirs {
				name := d
				if !single {
					name = filepath.ToSlash(filepath.Join(prefix, d))
				}
				if !seenDir[name] {
					seenDir[name] = true
					emptyDirs = append(emptyDirs, name)
				}
			}
			continue
		}

		excluded := false
		for _, pat := range excludes {
			if ok, _ := filepath.Match(pat, filepath.Base(r.path)); ok {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if r.isLink {
			addUnique(FileRef{
				Abs: r.abs, Rel: filepath.Base(r.path), Mode: r.mode, ModTime: r.modTime,
				IsSymlink: true, LinkTarget: r.target,
			})
			continue
		}
		addUnique(FileRef{
			Abs: r.abs, Rel: filepath.Base(r.path), Size: r.size,
			Mode: r.mode, ModTime: r.modTime,
		})
	}

	if len(all) == 0 && len(emptyDirs) == 0 {
		return nil, nil, fmt.Errorf("no files found")
	}
	return all, emptyDirs, nil
}
