package archive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrUnsafePath = errors.New("unsafe path in archive")

func cleanEntryName(name string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%w: %q (%s)", ErrUnsafePath, name, why)
	}
	if name == "" {
		return bad("empty name")
	}
	if strings.ContainsRune(name, 0) {
		return bad("NUL byte")
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return bad("absolute path")
	}
	if filepath.VolumeName(name) != "" || (len(name) >= 2 && name[1] == ':') {
		return bad("drive or volume prefix")
	}
	
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' })
	var clean []string
	for _, p := range parts {
		switch p {
		case ".":
			continue
		case "..":
			return bad("parent directory component")
		}
		if runtime.GOOS == "windows" && strings.ContainsRune(p, ':') {
			return bad("':' in name (alternate data stream)")
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return bad("no usable path components")
	}
	return strings.Join(clean, "/"), nil
}

// safeJoin returns the on-disk path for an archive entry name under root,
// guaranteeing the result is strictly inside root and that no existing
// directory component below root is a symlink.
func safeJoin(root, name string) (string, error) {
	clean, err := cleanEntryName(name)
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %q (resolves outside the output directory)", ErrUnsafePath, name)
	}
	if err := refuseSymlinkParents(root, rel, name); err != nil {
		return "", err
	}
	return p, nil
}

// refuseSymlinkParents fails if any existing parent directory of rel (below
// root) is a symlink. Missing components are fine; they will be created as
// real directories.
func refuseSymlinkParents(root, rel, name string) error {
	parts := strings.Split(rel, string(filepath.Separator))
	cur := root
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q (would be written through symlink %s)", ErrUnsafePath, name, cur)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %q (parent %s is not a directory)", ErrUnsafePath, name, cur)
		}
	}
	return nil
}

// createSafeFile creates (truncating) the file at path p, which must come
// from safeJoin. If something is already there and it is a symlink, the
// symlink itself is replaced rather than followed, so a symlink planted by
// an earlier entry can't redirect the write.
func createSafeFile(p string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(p); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
}
