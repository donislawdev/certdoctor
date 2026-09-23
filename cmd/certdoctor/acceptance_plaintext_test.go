//go:build acceptance

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
)

// TestTheShippedBinarySendsNoTLSToATargetWithoutIt is ADR100 observed on the
// wire rather than inferred from a counter inside the process.
//
// Measured on the bench 2026-09-22, before that decision: an http:// target got
// a ClientHello on its plain HTTP port and a FAIL for not answering it. The
// in-process checks replace the handshake port, so the one thing none of them
// can see is whether the SHIPPED binary still sends TLS bytes somewhere they
// were never asked for. This listener counts every byte that arrives.
//
// THE CONTROL RUN GOES FIRST, AND WITHOUT IT A ZERO BELOW PROVES NOTHING. An
// https:// run against the same port has to deliver bytes, or the counter is
// blind and the check would pass against a binary that sends a ClientHello to
// everything.
func TestTheShippedBinarySendsNoTLSToATargetWithoutIt(t *testing.T) {
	port, received := listenCountingBytes(t)

	runProgram(t, fmt.Sprintf("https://127.0.0.1:%d/", port), "--json", "--probe-timeout", "2")
	if received.Load() == 0 {
		t.Fatal("the control run with https:// delivered no bytes, so the counter proves nothing")
	}
	received.Store(0)

	r := runProgram(t, fmt.Sprintf("http://127.0.0.1:%d/", port), "--json", "--probe-timeout", "2")
	if n := received.Load(); n != 0 {
		t.Errorf("%d byte(s) reached a port the user named as http://, and a TCP connection sends none", n)
	}
	// NO LAYER FAILED, so the run is inconclusive rather than a diagnosis - the
	// code that moved from 4 to 5 with ADR100.
	if r.code != exitcode.Inconclusive.Int() {
		t.Errorf("a run against a reachable target without TLS ended with %d: %s", r.code, r.stderr)
	}

	var document struct {
		Layers []layerRow `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, row := range document.Layers {
		if row.ID != string(layer.TLS) && row.ID != string(layer.TrustMatrix) {
			continue
		}
		if row.Status != "UNKNOWN" || row.Reason != "nothing_to_check" {
			t.Errorf("%s answered %s/%s about a target without TLS: %s", row.ID, row.Status, row.Reason, row.Detail)
		}
	}
}

// listenCountingBytes accepts connections on a loopback port and adds up every
// byte any of them sends, until the test ends.
//
// EACH CONNECTION IS READ TO ITS END OR FOR A SECOND, WHICHEVER COMES FIRST. A
// ClientHello arrives at once and the client then waits for an answer that
// never comes, so the deadline is what ends that connection - and it is shorter
// than the probe timeout, so the run is never the one that gives up first.
func listenCountingBytes(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no loopback port to listen on: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	var received atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				n, _ := io.Copy(io.Discard, conn)
				received.Add(n)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, &received
}
