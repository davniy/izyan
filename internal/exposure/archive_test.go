package exposure

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createMockTGZ(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func createMockZIP(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestExtractManifests_TGZ(t *testing.T) {
	data, err := createMockTGZ(map[string]string{
		"values.yaml": "replicaCount: 2\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := extractManifestsFromTGZ(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractManifestsFromTGZ failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dest, "values.yaml"))
	if err != nil {
		t.Fatalf("expected values.yaml to exist: %v", err)
	}
	if string(content) != "replicaCount: 2\n" {
		t.Fatalf("unexpected content: %s", string(content))
	}
}

func TestExtractManifests_ZIP(t *testing.T) {
	data, err := createMockZIP(map[string]string{
		"templates/service.yaml": "kind: Service\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := extractManifestsFromZIP(bytes.NewReader(data), int64(len(data)), dest); err != nil {
		t.Fatalf("extractManifestsFromZIP failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dest, "templates", "service.yaml"))
	if err != nil {
		t.Fatalf("expected templates/service.yaml to exist: %v", err)
	}
	if string(content) != "kind: Service\n" {
		t.Fatalf("unexpected content: %s", string(content))
	}
}

func TestExtractManifests_ZipSlip(t *testing.T) {
	dest := t.TempDir()

	// 1. Test TGZ with Zip Slip
	tgzData, err := createMockTGZ(map[string]string{
		"../../evil.yaml": "evil: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	tgzErr := extractManifestsFromTGZ(bytes.NewReader(tgzData), dest)
	// Must be rejected or safely trapped
	evilPath := filepath.Join(dest, "../../evil.yaml")
	if _, err := os.Stat(evilPath); err == nil {
		t.Fatalf("Zip slip vulnerability in TGZ: evil.yaml written outside destDir: %s", evilPath)
	}
	if tgzErr == nil {
		// If not an error, it must not have written evil.yaml at all outside dest
		cleanDest := filepath.Clean(dest)
		if strings.HasPrefix(evilPath, cleanDest) {
			t.Fatalf("evilPath should be outside cleanDest")
		}
	}

	// 2. Test ZIP with Zip Slip
	zipData, err := createMockZIP(map[string]string{
		"../../evil_zip.yaml": "evil: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	destZip := t.TempDir()
	zipErr := extractManifestsFromZIP(bytes.NewReader(zipData), int64(len(zipData)), destZip)
	evilZipPath := filepath.Join(destZip, "../../evil_zip.yaml")
	if _, err := os.Stat(evilZipPath); err == nil {
		t.Fatalf("Zip slip vulnerability in ZIP: evil_zip.yaml written outside destDir: %s", evilZipPath)
	}
	if zipErr == nil {
		t.Fatalf("expected Zip Slip error for ZIP with traversal path, got nil")
	}

	// 3. Test Windows backslash separators traversal
	winData, err := createMockZIP(map[string]string{
		"sub\\..\\..\\evil_win.yaml": "evil: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	destWin := t.TempDir()
	winErr := extractManifestsFromZIP(bytes.NewReader(winData), int64(len(winData)), destWin)
	if winErr == nil {
		t.Fatalf("expected Zip Slip error for ZIP with Windows backslash traversal, got nil")
	}
}

func TestExtractManifests_RootDirEntry(t *testing.T) {
	dest := t.TempDir()

	// TGZ with root dir entries "." and "./"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Add "." dir entry
	_ = tw.WriteHeader(&tar.Header{
		Name:     ".",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	// Add "./templates" dir entry
	_ = tw.WriteHeader(&tar.Header{
		Name:     "./templates",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	// Add regular yaml
	content := []byte("kind: Service\n")
	_ = tw.WriteHeader(&tar.Header{
		Name:     "./templates/service.yaml",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	if err := extractManifestsFromTGZ(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("unexpected error extracting TGZ with root dir entries: %v", err)
	}
	extracted := filepath.Join(dest, "templates/service.yaml")
	if _, err := os.Stat(extracted); err != nil {
		t.Fatalf("service.yaml not found after TGZ extraction: %v", err)
	}
}

func TestExtractManifests_FilterNonYAML(t *testing.T) {
	dest := t.TempDir()
	largeContent := strings.Repeat("a", (1<<20)+10)
	data, err := createMockTGZ(map[string]string{
		"readme.txt": "hello world\n",
		"binary.bin": "\x00\x01\x02\x03",
		"large.yaml": largeContent,
		"valid.yaml": "kind: Service\n",
		"valid.yml":  "kind: Deployment\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := extractManifestsFromTGZ(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extract failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "readme.txt")); err == nil {
		t.Error("readme.txt should not have been extracted")
	}
	if _, err := os.Stat(filepath.Join(dest, "binary.bin")); err == nil {
		t.Error("binary.bin should not have been extracted")
	}
	if _, err := os.Stat(filepath.Join(dest, "large.yaml")); err == nil {
		t.Error("large.yaml (> 1MB) should not have been extracted")
	}
	if _, err := os.ReadFile(filepath.Join(dest, "valid.yaml")); err != nil {
		t.Errorf("valid.yaml should exist: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(dest, "valid.yml")); err != nil {
		t.Errorf("valid.yml should exist: %v", err)
	}
}

func TestExtractArchive(t *testing.T) {
	dest := t.TempDir()

	// TGZ by extension
	tgzData, err := createMockTGZ(map[string]string{"chart/values.yaml": "app: test\n"})
	if err != nil {
		t.Fatal(err)
	}
	tgzFile := filepath.Join(dest, "archive.tgz")
	if err := os.WriteFile(tgzFile, tgzData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir1 := filepath.Join(dest, "out1")
	if err := extractArchive(tgzFile, outDir1); err != nil {
		t.Fatalf("extractArchive tgz failed: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(outDir1, "chart", "values.yaml")); err != nil {
		t.Fatalf("expected chart/values.yaml in out1: %v", err)
	}

	// ZIP by extension
	zipData, err := createMockZIP(map[string]string{"chart/service.yaml": "kind: Service\n"})
	if err != nil {
		t.Fatal(err)
	}
	zipFile := filepath.Join(dest, "archive.zip")
	if err := os.WriteFile(zipFile, zipData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir2 := filepath.Join(dest, "out2")
	if err := extractArchive(zipFile, outDir2); err != nil {
		t.Fatalf("extractArchive zip failed: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(outDir2, "chart", "service.yaml")); err != nil {
		t.Fatalf("expected chart/service.yaml in out2: %v", err)
	}

	// Unknown format
	badFile := filepath.Join(dest, "bad.txt")
	if err := os.WriteFile(badFile, []byte("not an archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(badFile, filepath.Join(dest, "out3")); err == nil {
		t.Error("expected error for bad.txt, got nil")
	}
}
