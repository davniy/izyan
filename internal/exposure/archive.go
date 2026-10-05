package exposure

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxManifestSize  = 1 << 20  // 1MB per file
	maxManifestFiles = 512      // total extracted manifests
	maxArchiveBytes  = 64 << 20 // 64MB decompressed stream cap
)

// extractManifestsFromTGZ extracts .yaml and .yml files (<= 1MB) from a gzipped tar archive.
// Applies strict Zip Slip protection against directory traversal. The gzip
// stream is capped: skipped members still consume decompressed bytes, so a
// decompression bomb terminates the scan instead of burning CPU.
func extractManifestsFromTGZ(reader io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzr.Close()

	cleanDest := filepath.Clean(destDir)
	tr := tar.NewReader(io.LimitReader(gzr, maxArchiveBytes))
	extracted := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Filter: only regular files
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		// Filter: only .yaml and .yml
		ext := strings.ToLower(filepath.Ext(header.Name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		// Filter: max size 1MB
		if header.Size > maxManifestSize || header.Size < 0 {
			continue
		}
		extracted++
		if extracted > maxManifestFiles {
			return fmt.Errorf("archive exceeds manifest file limit (%d)", maxManifestFiles)
		}

		// Zip Slip protection: normalize backslashes from Windows archives
		cleanName := strings.ReplaceAll(header.Name, "\\", "/")
		target := filepath.Join(cleanDest, filepath.Clean("/"+cleanName))
		if !strings.HasPrefix(target, cleanDest+string(filepath.Separator)) || strings.HasPrefix(filepath.Clean(cleanName), "..") {
			return fmt.Errorf("insecure path in archive: %s", header.Name)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}

		lr := io.LimitReader(tr, maxManifestSize+1)
		n, err := io.Copy(outFile, lr)
		outFile.Close()
		if err != nil {
			os.Remove(target)
			return err
		}
		if n > maxManifestSize {
			os.Remove(target)
			continue
		}
	}

	return nil
}

// extractManifestsFromZIP extracts .yaml and .yml files (<= 1MB) from a zip archive.
// Applies strict Zip Slip protection against directory traversal.
func extractManifestsFromZIP(reader io.ReaderAt, size int64, destDir string) error {
	zr, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}

	cleanDest := filepath.Clean(destDir)
	extracted := 0
	for _, f := range zr.File {
		// Filter: skip directories and non-regular files
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}

		// Filter: only .yaml and .yml
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		// Filter: max size 1MB
		if f.UncompressedSize64 > maxManifestSize {
			continue
		}
		extracted++
		if extracted > maxManifestFiles {
			return fmt.Errorf("archive exceeds manifest file limit (%d)", maxManifestFiles)
		}

		// Zip Slip protection: normalize backslashes from Windows archives
		cleanName := strings.ReplaceAll(f.Name, "\\", "/")
		target := filepath.Join(cleanDest, filepath.Clean("/"+cleanName))
		if !strings.HasPrefix(target, cleanDest+string(filepath.Separator)) || strings.HasPrefix(filepath.Clean(cleanName), "..") {
			return fmt.Errorf("insecure path in archive: %s", f.Name)
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			rc.Close()
			return err
		}

		outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}

		lr := io.LimitReader(rc, maxManifestSize+1)
		n, err := io.Copy(outFile, lr)
		rc.Close()
		outFile.Close()
		if err != nil {
			os.Remove(target)
			return err
		}
		if n > maxManifestSize {
			os.Remove(target)
			continue
		}
	}

	return nil
}

// extractArchive extracts manifest files from a .tgz, .tar.gz, or .zip archive to destDir.
// It detects the archive format by magic bytes or file extension.
func extractArchive(archivePath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	// Detect format via magic bytes
	var magic [4]byte
	n, _ := io.ReadFull(f, magic[:])

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	isTGZ := false
	isZIP := false

	if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		isTGZ = true
	} else if n >= 4 && magic[0] == 0x50 && magic[1] == 0x4b {
		isZIP = true
	} else {
		lower := strings.ToLower(archivePath)
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
			isTGZ = true
		} else if strings.HasSuffix(lower, ".zip") {
			isZIP = true
		}
	}

	if isTGZ {
		return extractManifestsFromTGZ(f, destDir)
	}
	if isZIP {
		return extractManifestsFromZIP(f, info.Size(), destDir)
	}

	return fmt.Errorf("unsupported archive format: %s", archivePath)
}
