package widget

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/internal/cache"
	"fyne.io/fyne/v2/test"
)

// This file is part of the Evonet fork of Fyne (see evonet/docs/vendored-fyne.md).
//
// It guards the local patch to textRenderer.Refresh: converting each segment to
// []rune once per refresh instead of once per row. Without the patch the cost of
// a refresh is O(rows * runes), and Evonet's GUI log view - which keeps up to
// 1,000 lines in a single TextSegment - spent ~400 ms and ~700 MB per refresh on
// the macOS main thread, freezing the window.

// evonetLogWidth is the content width of Evonet's GUI log view.
const evonetLogWidth = 660

// evonetLogText returns lines lines of log output shaped like Evonet's GUI log.
func evonetLogText(lines int) string {
	out := make([]string, lines)
	for i := range out {
		out[i] = fmt.Sprintf("2026-10-26T12:%02d:%02d [info] executor: step %d finished in %dms",
			(i/60)%60, i%60, i, 5+i%250)
	}
	return strings.Join(out, "\n")
}

// evonetLogRichText builds the widget the way Evonet's log view does: the whole
// history lives in one RichText whose text is a single multi-line TextSegment.
func evonetLogRichText(lines int) *RichText {
	rt := NewRichTextWithText(evonetLogText(lines))
	rt.Wrapping = fyne.TextWrapWord
	rt.Resize(fyne.NewSize(evonetLogWidth, 400))
	return rt
}

// TestEvonetRichTextRefreshAllocs fails if a single refresh of a 1,000-line log
// allocates an amount consistent with the old quadratic path. The patched code
// allocates ~3 MiB; the quadratic version allocated ~700 MiB, so the 64 MiB
// bound is far from both and does not depend on machine speed.
func TestEvonetRichTextRefreshAllocs(t *testing.T) {
	test.NewApp()

	const lines = 1000
	rt := evonetLogRichText(lines)
	renderer := cache.Renderer(rt)
	renderer.Refresh() // warm up caches so the measurement only covers the row loop

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	renderer.Refresh()
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	const limit = 64 << 20 // 64 MiB
	if allocated > limit {
		t.Fatalf("%d-line RichText refresh allocated %.1f MiB, want < %d MiB: "+
			"textRenderer.Refresh has probably regressed to converting the segment "+
			"text to []rune once per row", lines, float64(allocated)/(1<<20), limit>>20)
	}
	t.Logf("%d-line RichText refresh allocated %.2f MiB", lines, float64(allocated)/(1<<20))

	// The cached rune slice must not disturb the per-row slicing: the first and
	// last rendered rows still have to carry the first and last source lines.
	texts := richTextRenderTexts(rt)
	if len(texts) == 0 {
		t.Fatal("no rendered rows")
	}
	src := strings.Split(evonetLogText(lines), "\n")
	if got, want := texts[0].Text, src[0]; got != want {
		t.Errorf("first row = %q, want %q", got, want)
	}
	if got, want := texts[len(texts)-1].Text, src[len(src)-1]; got != want {
		t.Errorf("last row = %q, want %q", got, want)
	}
}

// BenchmarkEvonetRichTextRefresh records the cost of one refresh for the log
// sizes Evonet actually reaches. Re-run it after bumping Fyne: time must stay
// linear in the number of lines (about 6 ms / 3 MiB at 1,000 lines on an
// amd64 development machine).
func BenchmarkEvonetRichTextRefresh(b *testing.B) {
	for _, lines := range []int{250, 500, 1000} {
		b.Run(fmt.Sprintf("%dLines", lines), func(b *testing.B) {
			test.NewApp()
			rt := evonetLogRichText(lines)
			renderer := cache.Renderer(rt)
			renderer.Refresh() // warm up

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				renderer.Refresh()
			}
		})
	}
}
