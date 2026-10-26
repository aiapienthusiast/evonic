# Vendored Fyne — local patches and how to re-verify them

Evonet pins Fyne `v2.7.3` and builds against a local copy:

```
// evonet/go.mod
require fyne.io/fyne/v2 v2.7.3
replace fyne.io/fyne/v2 => ./third_party/fyne
```

The copy under `third_party/fyne` is a **partial** tree: only the packages
Evonet compiles are present. `data/` and `internal/build/` are not committed
(they are excluded by the repository root `.gitignore`), so
`go test ./widget/...` does **not** run inside `third_party/fyne` as-is; see
*Re-verifying a patch* below.

Every local change to the fork is listed here. When bumping Fyne, re-apply each
patch and re-run the checks.

## Patch inventory

| File | Patch | Why |
| --- | --- | --- |
| `internal/animation/runner.go` | Added `Runner.IsRunning()`. | Lets the desktop loop know whether animation frames are needed. |
| `internal/driver/glfw/loop.go` | Replaced the fixed 60 Hz `eventTick` with a blocking `WaitEventsTimeout`, added `eventLoopWakeup` + `processFrame()`, and wake the loop from `fyne.Do`. | Removed 10–60 idle wakeups/second that made macOS report the app as "using significant energy" (task #805). |
| `internal/driver/glfw/loop_desktop.go` | Added `waitEvents()` → `glfw.WaitEventsTimeout`, `wakeEventLoop()` → `glfw.PostEmptyEvent`. | Desktop implementation of the blocking loop. |
| `internal/driver/glfw/loop_wasm.go` | Added `waitEvents()` → `pollEvents`, `wakeEventLoop()` → no-op. | WebAssembly has no blocking wait. |
| `internal/driver/glfw/driver.go` | `Quit()` posts an empty event after closing `d.done`. | Otherwise shutdown waits for the event-loop timeout. |
| `widget/richtext.go` | `textRenderer.Refresh()` converts each segment to `[]rune` **once per refresh** (cached per segment) instead of once per row. | Fixed the macOS GUI freeze, see below. |

### `widget/richtext.go` — the GUI freeze fix

`textRenderer.Refresh()` iterates over every row and originally ran
`runes := []rune(textSeg.Text)` inside that loop. Evonet's log view keeps up to
1,000 lines in a **single** `TextSegment`, so one refresh converted the whole
text once per line: `O(rows × runes)`, quadratic in log size.

Measured on Fyne 2.7.3 (Go 1.24, 660 px wide, word wrap, ~60-char lines,
`cache.Renderer(w).Refresh()` after warm-up):

| log lines | before: time / allocated | after: time / allocated |
| ---: | ---: | ---: |
| 250 | 9.6 ms / 15.7 MiB | 0.60 ms / 0.09 MiB |
| 500 | 45.6 ms / 62.6 MiB | 0.73 ms / 0.19 MiB |
| 1,000 | 167.6 ms / 250 MiB | **1.70 ms / 0.37 MiB** |

End-to-end `RichText.Refresh()` (which also rebuilds row bounds) at 1,000 lines:
**185 ms → 5.0 ms**.

The log flusher asks for a render at most every 100 ms, so before the patch the
macOS main thread was busy for longer than the interval between renders: AppKit
never got to process clicks and the window appeared frozen. After the patch a
render takes ~5 % of the frame budget.

The patch is intentionally minimal: rows are emitted in segment order, so the
last-converted segment is almost always the current one, and
`TextSegment.Update` never mutates `Text` during a refresh. Multi-segment rows,
ellipsis and concealed (password) segments still slice the same indices from the
same rune slice.

## Regression test

`third_party/fyne/widget/richtext_evonet_test.go` (new file, not upstream) adds:

* `TestEvonetRichTextRefreshAllocs` — one refresh of a 1,000-line segment must
  allocate **< 64 MiB**. Patched: 0.37 MiB. Unpatched: 250 MiB (fails). It also
  asserts that the first and last rendered rows still contain the first and last
  source lines, so a broken rune cache cannot pass silently.
* `BenchmarkEvonetRichTextRefresh{250,500,1000}Lines` — records time and
  allocation per refresh for the sizes Evonet actually reaches.

## Re-verifying a patch

Because the vendored tree is partial, run the test against a complete Fyne
2.7.3 checkout with the fork's files copied in:

```sh
# 1. Fetch the exact version Evonet pins.
go mod download fyne.io/fyne/v2@v2.7.3

# 2. Copy the fork over the pristine module (the fork only differs in the files
#    listed above).
rsync -a "$(go env GOMODCACHE)/fyne.io/fyne/v2@v2.7.3/" /tmp/fyne-verify/
rsync -a evonet/third_party/fyne/ /tmp/fyne-verify/
chmod -R u+w /tmp/fyne-verify

# 3. Run the guarded test and the benchmark.
cd /tmp/fyne-verify
go test ./widget/ -run 'EvonetRichText' -count=1 -v
go test ./widget/ -run XXX -bench 'EvonetRichTextRefresh' -benchtime 20x

# 4. Run the upstream RichText tests to confirm the patch changed no behaviour.
go test ./widget/ -run 'RichText|Text_' -count=1
```

On a Mac (where the GUI can be built natively) `make build-gui-macos` exercises
the patches directly; the verification procedure for the freeze is in
`docs/macos-freeze-verification.md`.

## Bumping Fyne

1. Copy the new upstream version over `third_party/fyne` (keeping the fork's
   `.gitignore` handling in mind — see the note at the top).
2. Re-apply every patch from the inventory: `grep -n "Evonet patch" -r
   third_party/fyne` lists the patched hunks.
3. Run the checks in *Re-verifying a patch*; the 1,000-line row must stay under
   64 MiB and the benchmark must stay linear.
4. Run `go test ./...` in `evonet/` and the headless build matrix.

## Known limitation

The desktop event loop waits up to **3600 s** for a native event when the UI is
idle (`timeout := 3600.0` in `loop.go`). `fyne.Do` posts an empty event and
blocks until the closure runs, so a lost wakeup would stall that caller for up
to an hour. This is by design for power consumption (task #805) and is *not*
changed here; if a future change ever needs a watchdog, bound that timeout to a
few seconds instead.
