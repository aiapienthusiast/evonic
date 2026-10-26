package gui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendoredFyneKeepsRichTextRefreshPatch guards the local Fyne patch that
// fixed the macOS GUI freeze (see docs/vendored-fyne.md).
//
// The GUI packages are only compiled for darwin/windows, and the vendored Fyne
// tree is a partial copy, so CI on Linux cannot compile or run the patched
// renderer. This test reads the source instead: it fails if a future Fyne bump
// silently restores the per-row []rune conversion, which made a 1,000-line log
// refresh quadratic (168 ms / 250 MiB per refresh) and froze the window.
func TestVendoredFyneKeepsRichTextRefreshPatch(t *testing.T) {
	path := filepath.Join("..", "..", "third_party", "fyne", "widget", "richtext.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vendored richtext.go: %v", err)
	}

	body, ok := functionBody(string(raw), "func (r *textRenderer) Refresh() {")
	if !ok {
		t.Fatalf("%s does not contain textRenderer.Refresh", path)
	}

	if strings.Contains(body, "[]rune(textSeg.Text)") {
		t.Error("textRenderer.Refresh converts segment text to []rune inside the row loop; " +
			"that is the quadratic path that froze the macOS GUI (see docs/vendored-fyne.md)")
	}
	if !strings.Contains(body, "runesFor(") {
		t.Error("textRenderer.Refresh no longer uses the per-segment rune cache; " +
			"the Evonet patch was probably lost while updating Fyne (see docs/vendored-fyne.md)")
	}
}

// functionBody returns the body of the top-level function whose declaration is
// exactly decl, up to the start of the next top-level declaration.
func functionBody(src, decl string) (string, bool) {
	start := strings.Index(src, decl)
	if start < 0 {
		return "", false
	}
	rest := src[start+len(decl):]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end], true
}
