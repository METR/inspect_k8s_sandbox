package main

import (
	"fmt"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// answered is the records the forwarder gives a question of kind for name.
func answered(t *testing.T, n *names, name string, kind dnsmessage.Type) []dnsmessage.Resource {
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
	if err := reply.Unpack(n.answer(packed)); err != nil || reply.ID != 7 || !reply.Response || reply.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("the answer about %s is %+v, %v: want a reply to the question", name, reply.Header, err)
	}
	return reply.Answers
}

func TestLookupGetsANamesOwnAddressAndNoneOfIPv6(t *testing.T) {
	n := newNames()
	first := answered(t, n, "example.com.", dnsmessage.TypeA)
	again := answered(t, n, "EXAMPLE.com.", dnsmessage.TypeA)
	other := answered(t, n, "example.org.", dnsmessage.TypeA)
	if len(first) != 1 || len(again) != 1 || len(other) != 1 {
		t.Fatalf("answers of %d, %d and %d records: want one address each", len(first), len(again), len(other))
	}
	a, b, c := first[0].Body.(*dnsmessage.AResource).A, again[0].Body.(*dnsmessage.AResource).A, other[0].Body.(*dnsmessage.AResource).A
	if a != b || a == c || n.named(n.address("example.com")) != "example.com" {
		t.Fatalf("example.com at %v and %v, example.org at %v: want one address a name, that says which", a, b, c)
	}
	// A client that got an IPv6 address here would connect to it, and no rule sends that anywhere.
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
		if records := answered(t, n, "example.com.", kind); len(records) != 0 {
			t.Fatalf("a question of type %v got %v: want no record", kind, records)
		}
	}
}

func TestNameWhoseAddressWentToAnotherGetsANewOne(t *testing.T) {
	n := newNames()
	first := n.address("first.example")
	for i := range 1 << (32 - nameRange.Bits()) { // more names than the range has addresses
		n.address(fmt.Sprintf("%d.example", i))
	}
	if n.named(first) == "first.example" {
		t.Fatalf("after a range of other names, %v still stands for the first", first)
	}
	// A connection to the address it has now must not be asked for under the name that took its old one.
	if now := n.address("first.example"); n.named(now) != "first.example" {
		t.Fatalf("first.example is at %v, which stands for %q", now, n.named(now))
	}
}
