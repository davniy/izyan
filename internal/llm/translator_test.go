package llm

import (
	"context"
	"strings"
	"testing"
)

func TestTranslatorNilClient(t *testing.T) {
	var tr Translator
	if _, err := tr.Translate(context.Background(), "text"); err == nil {
		t.Fatal("nil client must error")
	}
	if got := tr.ModelName(); got != "" {
		t.Fatalf("nil client model=%q", got)
	}
}

func TestTranslatorReturnsContent(t *testing.T) {
	client, srv := mockServer(t, "Краткое описание уязвимости")
	defer srv.Close()
	tr := Translator{Client: client}
	got, err := tr.Translate(context.Background(), "A short vulnerability summary")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Краткое описание уязвимости" {
		t.Fatalf("translation=%q", got)
	}
	if tr.ModelName() != "m" {
		t.Fatalf("model=%q", tr.ModelName())
	}
}

func TestTranslatorStripsSurroundingQuotes(t *testing.T) {
	client, srv := mockServer(t, `"Переведённый текст"`)
	defer srv.Close()
	got, err := Translator{Client: client}.Translate(context.Background(), "some text")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Переведённый текст" {
		t.Fatalf("quotes not stripped: %q", got)
	}
}

func TestTranslatorRefusal(t *testing.T) {
	client, srv := mockServer(t, "I'm sorry, but I cannot help with that")
	defer srv.Close()
	if _, err := (Translator{Client: client}).Translate(context.Background(), "text"); err == nil {
		t.Fatal("refusal must error")
	}
}

func TestTranslatorEmptyOutput(t *testing.T) {
	client, srv := mockServer(t, "   ")
	defer srv.Close()
	_, err := (Translator{Client: client}).Translate(context.Background(), "text")
	if err == nil || !strings.Contains(err.Error(), "empty translation") {
		t.Fatalf("empty output must error, got %v", err)
	}
}
