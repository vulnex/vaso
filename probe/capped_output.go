package main

import "bytes"

// maxCommandOutputBytes bounds what the probe keeps of one stream of one
// command: a command printing without end (a looping shim, a huge policy
// dump) filled memory and the snapshot.
const maxCommandOutputBytes = 8 << 20

// commandOutputTruncated ends a stream cut at maxCommandOutputBytes.
const commandOutputTruncated = "\n[vaso-probe: output truncated at 8 MiB]\n"

// cappedBuffer keeps the first max bytes written to it and drops the rest,
// reporting every write as complete (a short write would fail the command).
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func newCappedBuffer(max int) *cappedBuffer { return &cappedBuffer{max: max} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// String is what was kept, marked when the rest was dropped.
func (b *cappedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + commandOutputTruncated
	}
	return b.buf.String()
}
