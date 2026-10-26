# Verifying the GUI freeze fix on macOS

Related: `docs/vendored-fyne.md` (why the vendored Fyne fork exists),
`docs/logwriter-energy.md` (the idle-energy work in the same code path).

## What was wrong

Evonet's GUI log view keeps up to 1,000 lines in a single `RichText`
`TextSegment`. Fyne's `textRenderer.Refresh()` converted that entire segment to
`[]rune` once **per row**, so one refresh cost `O(lines × characters)`:
~168 ms and ~250 MiB at 1,000 lines. The log flusher requests a render every
100 ms, so the Cocoa main thread was permanently busy in `Refresh()` + GC and
stopped servicing clicks. The buffer only reaches that size after hours of use,
which is why the freeze looked like "after a long time running".

The fix hoists the conversion out of the row loop (`third_party/fyne/widget/
richtext.go`), and the log writer now keeps at most one render queued on the UI
thread. A 1,000-line refresh costs ~5 ms end to end.

## Rebuild

On a Mac with Xcode command line tools:

```sh
cd evonet
make build-gui-macos          # produces dist/Evonet.app
open dist/Evonet.app
```

## Reproduce the old condition

The freeze depends on the log buffer being full, not on wall-clock time. To fill
it quickly, drive enough output through the GUI log view — for example run
several `exec_bash` tasks from the chat that print more than 1,000 lines in
total. The view keeps the newest 1,000 lines.

## Checks

1. **Responsiveness with a full log.** With the view at its 1,000-line cap,
   click buttons, open menus and switch windows. The UI must respond
   immediately; before the fix it became unusable once the buffer passed a few
   hundred lines.
2. **CPU while connected and idle.** Expect near-zero CPU. Before the fix the
   render loop kept one core busy once the buffer was large.
3. **Long session.** Leave the app connected for an hour with normal activity
   and confirm it stays clickable. No memory growth is expected beyond the
   bounded 1,000-line buffer.

## If it still freezes

Sample the hung process; the main thread must **not** be in
`widget.(*textRenderer).Refresh`:

```sh
sample "$(pgrep -x Evonet)" 10 -file /tmp/evonet-sample.txt
open /tmp/evonet-sample.txt
```

- Main thread inside `textRenderer.Refresh` or `runtime.mallocgc` driven by it →
  the vendored patch is missing or was reverted; see
  `docs/vendored-fyne.md` → *Bumping Fyne*.
- Main thread elsewhere → capture goroutine stacks for the report:

```sh
kill -QUIT "$(pgrep -x Evonet)"      # dumps all goroutine stacks to stderr
```

Run the app from a terminal so the dump is visible, or capture it via Console.
