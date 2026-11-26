package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answered is the forwarder's reply to a question of kind for name: its code and its records.
func answered(t *testing.T, n *names, name string, kind dnsmessage.Type) (dnsmessage.RCode, []dnsmessage.Resource) {
	t.Helper()
	question := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}},
	}
	packed, err := question.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(n.answer(packed)); err != nil || reply.ID != 7 || !reply.Response {
		t.Fatalf("the answer about %s is %+v, %v: want a reply to the question", name, reply.Header, err)
	}
	return reply.RCode, reply.Answers
}

func TestLookupGetsANamesOwnAddressAndNoneOfIPv6(t *testing.T) {
	n := newNames("")
	_, first := answered(t, n, "example.com.", dnsmessage.TypeA)
	_, again := answered(t, n, "EXAMPLE.com.", dnsmessage.TypeA)
	_, other := answered(t, n, "example.org.", dnsmessage.TypeA)
	if len(first) != 1 || len(again) != 1 || len(other) != 1 {
		t.Fatalf("answers of %d, %d and %d records: want one address each", len(first), len(again), len(other))
	}
	a, b, c := first[0].Body.(*dnsmessage.AResource).A, again[0].Body.(*dnsmessage.AResource).A, other[0].Body.(*dnsmessage.AResource).A
	if at, _ := n.address("example.com"); a != b || a == c || n.named(at) != "example.com" {
		t.Fatalf("example.com at %v and %v, example.org at %v: want one address a name, that says which", a, b, c)
	}
	for name, kind := range map[string]dnsmessage.Type{
		// A client that got an IPv6 address here would connect to it, and no rule sends that anywhere.
		"example.com.": dnsmessage.TypeAAAA,
		"example.net.": dnsmessage.TypeTXT,
		// A sibling's short name, asked of DNS and not of /etc/hosts: the proxy refuses a name with no dot.
		"game.": dnsmessage.TypeA,
		// It would end the line the forwarder asks the proxy for it in.
		"a\r\nb.example.": dnsmessage.TypeA,
	} {
		if code, records := answered(t, n, name, kind); code != dnsmessage.RCodeSuccess || len(records) != 0 {
			t.Fatalf("a question of type %v for %q got code %v and %v: want no record", kind, name, code, records)
		}
	}
}

func TestAddressGoesToAnotherNameOnlyOnceItsOwnWasNotAskedForAWhile(t *testing.T) {
	n, now := newNames(""), time.Now()
	n.now = func() time.Time { now = now.Add(time.Microsecond); return now } // each lookup after the one before
	first, _ := n.address("first.example")
	second, _ := n.address("second.example")
	for i := 2; i < 1<<(32-nameRange.Bits())-2; i++ { // every other address of the range
		n.address(fmt.Sprintf("%d.example", i))
	}
	// A client may still hold the answer that named each address.
	if code, records := answered(t, n, "late.example.", dnsmessage.TypeA); code != dnsmessage.RCodeServerFailure || len(records) != 0 {
		t.Fatalf("with every address just given, one more name got code %v and %v: want a failure, and no address", code, records)
	}
	now = now.Add(time.Minute)
	n.address("first.example") // looked up again: its address stays its own
	if late, room := n.address("late.example"); !room || late != second || n.named(first) != "first.example" {
		t.Fatalf("late.example is at %v (%v), and %v stands for %q: want the address of the name asked for longest ago, %v", late, room, first, n.named(first), second)
	}
	// A connection to the address it has now must not be asked for under the name that took its old one.
	if now, _ := n.address("second.example"); n.named(now) != "second.example" || now == second {
		t.Fatalf("second.example is at %v, which stands for %q", now, n.named(now))
	}
}

func TestForwarderStartedAgainGivesNoAddressAnEarlierOneGaveAnotherName(t *testing.T) {
	kept := filepath.Join(t.TempDir(), "names")
	earlier, _ := newNames(kept).address("earlier.example")
	// A client that kept the earlier answer past its life would else reach the later name's host.
	again := newNames(kept)
	if later, _ := again.address("later.example"); later == earlier || again.named(earlier) != "" {
		t.Fatalf("after a restart later.example is at %v and %v stands for %q: want %v to stand for no name", later, earlier, again.named(earlier), earlier)
	}
	// One started once every address was given has none that is not an earlier answer's, until those have expired.
	os.WriteFile(kept, binary.BigEndian.AppendUint32(nil, 1<<(32-nameRange.Bits())-2), 0o600)
	last := newNames(kept)
	if addr, room := last.address("last.example"); room {
		t.Fatalf("a forwarder started after every address was given gave %v at once: want none while an earlier answer may be in use", addr)
	}
	last.now = func() time.Time { return last.since.Add(2 * nameTTL) }
	if _, room := last.address("last.example"); !room {
		t.Fatal("it has no address still, once the earlier answers have expired")
	}
}
