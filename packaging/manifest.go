// Package packaging seals and verifies signed artifact directories.
package packaging

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ManifestName   = "manifest.json"
	SignatureName  = "manifest.ed25519"
	ManifestSchema = "packages-go.artifact.v1"
)

// File is one payload entry authenticated by a manifest.
type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Manifest authenticates a complete artifact directory.
//
// MainProof, CIRunID, and ToolingSHA256 are declared optional: a manifest
// sealed without them is unchanged from before they existed (the fields are
// omitted from the JSON entirely and Verify does not require them), and a
// manifest sealed with them carries them inside the signed bytes, so
// tampering with any one of them after sealing invalidates the signature
// exactly like tampering with Files does. They are named for the general
// security properties they capture, not for any one caller's vocabulary, so
// other sealers (for example a publication-release pipeline) can populate
// the same fields for the same properties instead of inventing their own.
type Manifest struct {
	Schema    string `json:"schema"`
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	CreatedAt string `json:"createdAt"`
	Files     []File `json:"files"`

	// MainProof is an optional ahead/identical ancestry proof: it records
	// that the sealed revision is ahead of, or identical to, a named trunk
	// revision, for callers that must prove the artifact descends from a
	// specific reviewed commit before treating it as releasable. Nil is
	// valid; Verify does not require it.
	MainProof *MainProof `json:"mainProof,omitempty"`

	// CIRunID optionally binds the sealed artifact to one managed-CI run,
	// so a verifier can cross-check it against an out-of-band receipt from
	// that run instead of trusting the artifact's own claim alone. Zero
	// means absent; Verify does not require it.
	CIRunID int64 `json:"ciRunId,omitempty"`

	// ToolingSHA256 optionally records the SHA-256 of the installer or
	// tooling bytes that sealed this artifact, so that same tooling can
	// refuse to act on the artifact unless its own running bytes still
	// hash-match this value. Empty means absent; Verify does not require
	// it.
	ToolingSHA256 string `json:"toolingSHA256,omitempty"`
}

// MainProof is the ahead/identical ancestry proof carried by Manifest.
type MainProof struct {
	// Main is the trunk revision the proof is made against.
	Main string `json:"main"`
	// Target is the revision the proof describes.
	Target string `json:"target"`
	// Status is "ahead" or "identical".
	Status string `json:"status"`
}

// Metadata supplies provenance for a new manifest.
type Metadata struct {
	Version   string
	Revision  string
	CreatedAt time.Time

	// MainProof, CIRunID, and ToolingSHA256 are optional; the zero value of
	// each (nil, 0, "") omits the corresponding Manifest field entirely.
	MainProof     *MainProof
	CIRunID       int64
	ToolingSHA256 string
}

// Artifact reports the hashes emitted by Seal.
type Artifact struct {
	ManifestSHA256 string
	Signature      string
}

// Seal hashes every regular payload file and writes a detached Ed25519
// signature over the deterministic JSON manifest.
func Seal(ctx context.Context, directory string, metadata Metadata, privateKey ed25519.PrivateKey) (Artifact, error) {
	files, err := collectFiles(ctx, directory)
	if err != nil {
		return Artifact{}, err
	}
	manifest := Manifest{
		Schema: ManifestSchema, Version: metadata.Version, Revision: metadata.Revision,
		CreatedAt: metadata.CreatedAt.UTC().Format(time.RFC3339Nano), Files: files,
		MainProof: metadata.MainProof, CIRunID: metadata.CIRunID, ToolingSHA256: metadata.ToolingSHA256,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return Artifact{}, fmt.Errorf("marshal artifact manifest: %w", err)
	}
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureText := base64.StdEncoding.EncodeToString(signature)
	if err := writePrivateFile(filepath.Join(directory, ManifestName), manifestBytes); err != nil {
		return Artifact{}, err
	}
	if err := writePrivateFile(filepath.Join(directory, SignatureName), []byte(signatureText)); err != nil {
		return Artifact{}, err
	}
	digest := sha256.Sum256(manifestBytes)
	return Artifact{ManifestSHA256: hex.EncodeToString(digest[:]), Signature: signatureText}, nil
}

// Verify authenticates the detached signature and re-hashes the exact payload
// file set after transport.
func Verify(ctx context.Context, directory string, publicKey ed25519.PublicKey) (Manifest, error) {
	return VerifyAny(ctx, directory, publicKey)
}

// VerifyAny authenticates the detached signature against any one of the
// given trusted public keys, succeeding as soon as one authenticates it, then
// re-hashes the exact payload file set after transport. Callers rotating a
// signing key pass the current key plus any previous key(s) still needed to
// verify not-yet-superseded artifacts (e.g. older signed backups); once
// nothing trusts a retired key anymore, drop it from the list.
func VerifyAny(ctx context.Context, directory string, publicKeys ...ed25519.PublicKey) (Manifest, error) {
	if len(publicKeys) == 0 {
		return Manifest{}, fmt.Errorf("at least one trusted public key is required")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(directory, ManifestName))
	if err != nil {
		return Manifest{}, fmt.Errorf("read artifact manifest: %w", err)
	}
	signatureText, err := os.ReadFile(filepath.Join(directory, SignatureName))
	if err != nil {
		return Manifest{}, fmt.Errorf("read detached signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(string(signatureText))
	if err != nil {
		return Manifest{}, fmt.Errorf("decode detached signature: %w", err)
	}
	authenticated := false
	for _, publicKey := range publicKeys {
		if ed25519.Verify(publicKey, manifestBytes, signature) {
			authenticated = true
			break
		}
	}
	if !authenticated {
		return Manifest{}, fmt.Errorf("detached signature does not authenticate manifest against any trusted key")
	}

	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode artifact manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, err
	}
	if manifest.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("artifact manifest schema %q is unsupported", manifest.Schema)
	}
	actual, err := collectFiles(ctx, directory)
	if err != nil {
		return Manifest{}, err
	}
	if !equalFiles(manifest.Files, actual) {
		return Manifest{}, fmt.Errorf("artifact payload does not match signed manifest")
	}
	return manifest, nil
}

func collectFiles(ctx context.Context, directory string) ([]File, error) {
	var files []File
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if relative == "." || entry.IsDir() {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if relative == ManifestName || relative == SignatureName {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact contains symlink %q", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact contains non-regular file %q", relative)
		}
		digest, bytes, err := hashFile(path)
		if err != nil {
			return err
		}
		files = append(files, File{Path: relative, Bytes: bytes, SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk artifact directory: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	bytes, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), bytes, nil
}

func writePrivateFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("set %s mode: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("artifact manifest contains trailing JSON")
	}
	return nil
}

func equalFiles(left, right []File) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] || !safeRelativePath(left[index].Path) {
			return false
		}
	}
	return true
}

func safeRelativePath(path string) bool {
	if path == "" || filepath.IsAbs(path) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && clean != ".." && !strings.HasPrefix(clean, "../")
}
