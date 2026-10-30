package refindex

import (
	"context"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/fix"
	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// PatchFetcher is the fix-patch provider seam (fix.HTTPProvider in
// production, a stub in tests).
type PatchFetcher interface {
	Fetch(ctx context.Context, ref fix.Reference) (string, error)
}

// buildFixDiff assembles the auxiliary fix-diff block. The patch is never
// primary evidence for the locus: failures degrade to "unavailable",
// absent references and disabled fetching to "not_attempted".
func buildFixDiff(ctx context.Context, v *pbdomain.Vulnerability, fetcher PatchFetcher) FixDiff {
	fd := FixDiff{Status: FixDiffNotAttempted, Files: []FixDiffFile{}}
	if fetcher == nil {
		return fd
	}
	refs := (fix.Resolver{}).Resolve(*v)
	if len(refs) == 0 {
		return fd
	}
	fd.Status = FixDiffUnavailable
	for _, ref := range refs {
		patch, err := fetcher.Fetch(ctx, ref)
		if err != nil {
			continue
		}
		fd.Files = countDiffFiles(patch)
		fd.Status = FixDiffAvailable
		return fd
	}
	return fd
}

// countDiffFiles counts per-file +/- churn of a unified diff, sorted by
// path. File headers ("---"/"+++") are not content lines; "diff --git"
// starts a new file; deleted files take their name from the "--- a/"
// header.
func countDiffFiles(patch string) []FixDiffFile {
	order := []string{}
	churn := map[string]*FixDiffFile{}
	cur := ""
	oldPath := ""
	startFile := func(p string) {
		p = strings.TrimSpace(p)
		if i := strings.IndexAny(p, " \t"); i > 0 {
			p = p[:i] // drop timestamp suffixes
		}
		p = strings.TrimPrefix(p, "a/")
		p = strings.TrimPrefix(p, "b/")
		cur = p
		if cur == "" || cur == "/dev/null" {
			return
		}
		if _, ok := churn[cur]; !ok {
			churn[cur] = &FixDiffFile{Path: cur}
			order = append(order, cur)
		}
	}
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			cur, oldPath = "", ""
		case strings.HasPrefix(line, "--- "):
			oldPath = strings.TrimSpace(strings.TrimPrefix(line, "---"))
		case strings.HasPrefix(line, "+++ "):
			p := strings.TrimSpace(strings.TrimPrefix(line, "+++"))
			if p == "/dev/null" {
				// Deleted file: its name lives on the "--- a/" header.
				if oldPath != "" {
					startFile(oldPath)
				}
				continue
			}
			startFile(p)
		case cur != "" && strings.HasPrefix(line, "+"):
			churn[cur].Additions++
		case cur != "" && strings.HasPrefix(line, "-"):
			churn[cur].Deletions++
		}
	}
	out := make([]FixDiffFile, 0, len(order))
	for _, p := range order {
		out = append(out, *churn[p])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
