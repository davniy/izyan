package research

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func TestLoadTicketAbsent(t *testing.T) {
	if rec := loadTicket("", ""); rec != nil {
		t.Fatalf("empty path must yield no record: %+v", rec)
	}
}

func TestLoadTicketMissing(t *testing.T) {
	rec := loadTicket(filepath.Join(t.TempDir(), "absent.json"), "")
	if rec == nil || rec.ParseError != domain.TicketReasonInvalid ||
		rec.Path == "" || rec.SHA256 != "" || rec.Claims != nil {
		t.Fatalf("missing path record %+v", rec)
	}
}

func TestLoadTicketJSON(t *testing.T) {
	body := `{"id":"CASE-227168","vulnerability":"GO-2026-4526","aliases":["CVE-2026-32287"],"component":"DEMO","product":"Demo Mesh","release":"Demo Mesh 1.10.3","package":"github.com/antchfx/xpath","version":"1.3.2"}`
	p := writeTicket(t, t.TempDir(), "ticket.json", body)
	rec := loadTicket(p, "")
	if rec == nil || rec.ParseError != "" {
		t.Fatalf("valid ticket errored: %+v", rec)
	}
	sum := sha256.Sum256([]byte(body))
	if rec.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %q, want sha256 of the ticket bytes", rec.SHA256)
	}
	want := &domain.TicketClaims{
		Product: "Demo Mesh", ProductVersion: "Demo Mesh 1.10.3",
		Component: "DEMO",
		Package:   "github.com/antchfx/xpath", PackageVersion: "1.3.2",
		AdvisoryIDs: []string{"CVE-2026-32287"},
	}
	if !reflect.DeepEqual(rec.Claims, want) {
		t.Fatalf("claims %+v, want %+v", rec.Claims, want)
	}
}

func TestLoadTicketSelectsByID(t *testing.T) {
	body := `[
	  {"id":"APP-1","vulnerability":"GO-2026-4526","package":"github.com/a/one","version":"1.0.0"},
	  {"id":"APP-2","vulnerability":"GO-2026-4526","package":"github.com/b/two","version":"2.0.0"}
	]`
	p := writeTicket(t, t.TempDir(), "tickets.json", body)
	rec := loadTicket(p, "app-2")
	if rec == nil || rec.Claims == nil || rec.Claims.Package != "github.com/b/two" ||
		rec.Claims.PackageVersion != "2.0.0" {
		t.Fatalf("selection record %+v", rec)
	}
}

func TestLoadTicketIDNotFound(t *testing.T) {
	body := `[{"id":"APP-1","vulnerability":"GO-2026-4526","package":"github.com/a/one"}]`
	p := writeTicket(t, t.TempDir(), "tickets.json", body)
	rec := loadTicket(p, "APP-9")
	if rec == nil || rec.ParseError != domain.TicketReasonInvalid || rec.Claims != nil {
		t.Fatalf("absent selection must degrade to INVALID: %+v", rec)
	}
	if rec.SHA256 == "" {
		t.Fatal("digest must still pin the consumed bytes")
	}
}

// The real tracker text (case-03 shape): the version label may not
// hijack "Версия продукта:" — the package axis comes out of the
// library/PURL declarations.
func TestLoadTicketText(t *testing.T) {
	body := `Новая потенциальная уязвимость в Demo Mesh 1.10.3
Версия продукта: Demo Mesh 1.10.3 Тип версии продукта: HOTFIX Ссылка на Project: https://project.example.org/erp/productVersion/DEMO.14/main Ссылка на дистрибутив: https://portal.example.org/repository/demo_prod/_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip Компонент: DEMO 1.1.1-2397 Библиотека: github.com/antchfx/xpath 1.3.2 PURL: pkg:golang/github.com/antchfx/xpath@1.3.2 Алиасы на уязвимость: GO-2026-4526, CVE-2026-32287 Описание уязвимости: xpath allocation overflow
`
	p := writeTicket(t, t.TempDir(), "ticket.txt", body)
	rec := loadTicket(p, "")
	if rec == nil || rec.Claims == nil {
		t.Fatalf("text ticket record %+v", rec)
	}
	if rec.Claims.Package != "github.com/antchfx/xpath" || rec.Claims.PackageVersion != "1.3.2" {
		t.Fatalf("text claims %+v, want xpath 1.3.2", rec.Claims)
	}
	if rec.Claims.ProductVersion != "Demo Mesh 1.10.3" {
		t.Fatalf("release %+v, want the product+version only, no trailing labels", rec.Claims)
	}
	if rec.Claims.Component != "DEMO 1.1.1-2397" {
		t.Fatalf("component %+v, want DEMO 1.1.1-2397 (never crossing into Библиотека:/PURL:)", rec.Claims)
	}
	if len(rec.Claims.AdvisoryIDs) == 0 {
		t.Fatalf("text claims dropped advisory aliases: %+v", rec.Claims)
	}
}

// The same claims must come out of the JSON ticket and the labelled
// text form: identical package axis, component, product version and
// advisory ids.
func TestLoadTicketTextMatchesJSON(t *testing.T) {
	jsonBody := `{"vulnerability":"GO-2026-4526","aliases":["CVE-2026-32287"],"component":"DEMO","release":"Demo Mesh 1.10.3","package":"github.com/antchfx/xpath","version":"1.3.2"}`
	textBody := `GO-2026-4526 CVE-2026-32287
package: github.com/antchfx/xpath
version: 1.3.2
Компонент: DEMO
Версия продукта: Demo Mesh 1.10.3
`
	dir := t.TempDir()
	jrec := loadTicket(writeTicket(t, dir, "ticket.json", jsonBody), "")
	trec := loadTicket(writeTicket(t, dir, "ticket.txt", textBody), "")
	if jrec == nil || jrec.Claims == nil || trec == nil || trec.Claims == nil {
		t.Fatalf("records j=%+v t=%+v", jrec, trec)
	}
	if !reflect.DeepEqual(trec.Claims, jrec.Claims) {
		t.Fatalf("text claims %+v != JSON claims %+v", trec.Claims, jrec.Claims)
	}
}

func TestLoadTicketUnparsable(t *testing.T) {
	p := writeTicket(t, t.TempDir(), "ticket.json", `{not json`)
	rec := loadTicket(p, "")
	if rec == nil || rec.ParseError != domain.TicketReasonInvalid || rec.Claims != nil {
		t.Fatalf("unparsable record %+v", rec)
	}
	if rec.SHA256 == "" {
		t.Fatal("digest must still pin the consumed bytes")
	}
}

// Stdin ("-") is a first-class ticket source: the record cites no
// basename but still pins the consumed bytes.
func TestLoadTicketStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	body := `{"vulnerability":"GO-2026-4526","package":"github.com/antchfx/xpath","version":"1.3.2"}`
	if _, err := w.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	rec := loadTicket("-", "")
	if rec == nil || rec.Claims == nil || rec.Claims.PackageVersion != "1.3.2" {
		t.Fatalf("stdin record %+v", rec)
	}
	sum := sha256.Sum256([]byte(body))
	if rec.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("stdin digest must pin the piped bytes")
	}
}

func TestLoadTicketDistributionLocator(t *testing.T) {
	body := `GO-2026-4526 Ссылка на дистрибутив: https://user:secret@portal.example.org/_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip?token=secret Библиотека: example.com/snapdep 0.5.0`
	rec := loadTicket(writeTicket(t, t.TempDir(), "ticket.txt", body), "")
	if rec == nil || rec.DistributionURL != "https://portal.example.org/_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip" {
		t.Fatalf("ticket record %+v", rec)
	}
	if strings.Contains(rec.DistributionURL, "secret") {
		t.Fatal("ticket record retained locator credentials")
	}
}
