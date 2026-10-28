// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/greenbone/asset-identity/identity"
)

// One table per identifier type. A case either normalizes to want, is a placeholder (reported as invalid by
// NormalizeIdentifier and left out by Decide), or fails with err.

type typeCase struct {
	name        string
	raw         string
	want        string
	err         error
	placeholder bool
}

var (
	linuxKind   = identity.Scope{"kind": "linux_machine_id"}
	windowsKind = identity.Scope{"kind": "windows_machine_guid"}
)

func runTypeCases(t *testing.T, typ identity.IdentifierType, scope identity.Scope, cases []typeCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			input := identity.IdentifierValue{Type: typ, Value: tt.raw, Scope: scope}
			before := input.Clone()
			got, err := identity.NormalizeIdentifier(input)
			validation := identity.ValidateIdentifier(input)
			if !reflect.DeepEqual(input, before) {
				t.Fatal("input mutated")
			}
			if tt.err != nil || tt.placeholder {
				want := tt.err
				if tt.placeholder {
					want = identity.ErrInvalidIdentifierValue
				}
				if !errors.Is(err, want) || !errors.Is(validation, want) || !reflect.DeepEqual(got, identity.IdentifierValue{}) {
					t.Fatalf("got %+v err=%v validation=%v, want %v", got, err, validation, want)
				}
				if tt.placeholder {
					assertLeftOutByDecide(t, input)
				}
				return
			}
			if err != nil || validation != nil || got.Type != typ || got.Value != tt.want || !reflect.DeepEqual(got.Scope, scope) {
				t.Fatalf("got %+v err=%v validation=%v, want %q", got, err, validation, tt.want)
			}
			again, err := identity.NormalizeIdentifier(got)
			if err != nil || !identity.SameRepresentation(got, again) {
				t.Fatalf("not idempotent: %+v %v", again, err)
			}
			if same, err := identity.EqualIdentifiers(input, got); err != nil || !same {
				t.Fatalf("raw and normalized differ: %v %v", same, err)
			}
		})
	}
}

// assertLeftOutByDecide shows that a placeholder neither fails a decision nor matches: two assets carrying only the
// placeholder stay apart.
func assertLeftOutByDecide(t *testing.T, placeholder identity.IdentifierValue) {
	t.Helper()
	candidate := identity.Candidate{AssetKey: "K", Identifiers: []identity.IdentifierValue{placeholder}}
	got, err := identity.Decide(identity.Observation{Identifiers: []identity.IdentifierValue{placeholder}}, []identity.Candidate{candidate}, identity.GreenboneMatchPolicy())
	if err != nil || got.Action != identity.ActionCreate || len(got.MergeIndices) != 0 {
		t.Fatalf("placeholder took part in the decision: %+v %v", got, err)
	}
	matches, err := identity.MatchingIdentifiers([]identity.IdentifierValue{placeholder}, []identity.IdentifierValue{placeholder})
	if err != nil || len(matches) != 0 {
		t.Fatalf("placeholder reported as evidence: %v %v", matches, err)
	}
}

func TestNormalizeCloudIdentifier(t *testing.T) {
	runTypeCases(t, identity.TypeCloudIdentifier, nil, []typeCase{
		{name: "azure resource id is lower cased", raw: "/subscriptions/ABC/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1", want: "/subscriptions/abc/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1"},
		{name: "azure vm id is lower cased", raw: "8E5F4C1A-1B2C-4D3E-9F80-0123456789AB", want: "8e5f4c1a-1b2c-4d3e-9f80-0123456789ab"},
		{name: "aws arn is kept", raw: "arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc", want: "arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc"},
		{name: "aws instance id", raw: "i-0abcdef1234567890", want: "i-0abcdef1234567890"},
		{name: "gcp numeric id", raw: "1234567890123456789", want: "1234567890123456789"},
		{name: "surrounding space is trimmed", raw: " i-0abc\n", want: "i-0abc"},
		{name: "inner space is kept", raw: "Provider/Resource A", want: "provider/resource a"},
		{name: "longest allowed", raw: strings.Repeat("a", 2048), want: strings.Repeat("a", 2048)},
		{name: "too long", raw: strings.Repeat("a", 2049), err: identity.ErrInvalidIdentifierValue},
		{name: "blank", raw: "  ", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeGreenboneID(t *testing.T) {
	runTypeCases(t, identity.TypeGreenboneID, nil, []typeCase{
		{name: "guid", raw: "7d1c0b6e-6a3e-4c1f-9b52-1f7a2c3d4e5f", want: "7d1c0b6e-6a3e-4c1f-9b52-1f7a2c3d4e5f"},
		{name: "surrounding space is trimmed", raw: " 7d1c0b6e-6a3e-4c1f-9b52-1f7a2c3d4e5f \n", want: "7d1c0b6e-6a3e-4c1f-9b52-1f7a2c3d4e5f"},
		{name: "case is kept", raw: "7D1C0B6E", want: "7D1C0B6E"},
		{name: "opaque bytes are kept", raw: "Id-A\x00", want: "Id-A\x00"},
		{name: "longest allowed", raw: strings.Repeat("g", 2048), want: strings.Repeat("g", 2048)},
		{name: "too long", raw: strings.Repeat("g", 2049), err: identity.ErrInvalidIdentifierValue},
		{name: "blank", raw: "\t ", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeAgentID(t *testing.T) {
	runTypeCases(t, identity.TypeAgentID, nil, []typeCase{
		{name: "spelling is kept", raw: " WIN-NJAG2ND7ATT::3fa2c1d9 ", want: "WIN-NJAG2ND7ATT::3fa2c1d9"},
		{name: "any text", raw: "unknown", want: "unknown"},
		{name: "too long", raw: strings.Repeat("a", 2049), err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeMachineID(t *testing.T) {
	runTypeCases(t, identity.TypeMachineID, linuxKind, []typeCase{
		{name: "linux machine id", raw: "4c1b0c7e9f2d4a8b9c3e5f6a7b8c9d0e\n", want: "4c1b0c7e9f2d4a8b9c3e5f6a7b8c9d0e"},
		{name: "upper case is lowered", raw: "00112233445566778899AABBCCDDEEFF", want: "00112233445566778899aabbccddeeff"},
		{name: "not yet written", raw: "uninitialized", placeholder: true},
		{name: "not yet written in upper case", raw: "UNINITIALIZED\n", placeholder: true},
		{name: "all zero", raw: strings.Repeat("0", 32), placeholder: true},
		{name: "dashes are no linux machine id", raw: "4c1b0c7e-9f2d-4a8b-9c3e-5f6a7b8c9d0e", err: identity.ErrInvalidIdentifierValue},
		{name: "too short", raw: "4c1b0c7e", err: identity.ErrInvalidIdentifierValue},
		{name: "not hex", raw: "4c1b0c7e9f2d4a8b9c3e5f6a7b8c9d0g", err: identity.ErrInvalidIdentifierValue},
		{name: "malformed", raw: "malformed", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
	runTypeCases(t, identity.TypeMachineID, windowsKind, []typeCase{
		{name: "windows machine guid", raw: "{4C1B0C7E-9F2D-4A8B-9C3E-5F6A7B8C9D0E}", want: "4c1b0c7e-9f2d-4a8b-9c3e-5f6a7b8c9d0e"},
		{name: "without braces", raw: "4c1b0c7e-9f2d-4a8b-9c3e-5f6a7b8c9d0e", want: "4c1b0c7e-9f2d-4a8b-9c3e-5f6a7b8c9d0e"},
		{name: "all zero", raw: "00000000-0000-0000-0000-000000000000", placeholder: true},
		{name: "malformed", raw: "malformed", err: identity.ErrInvalidIdentifierValue},
	})
	for _, scope := range []identity.Scope{nil, {}, {"kind": "unknown"}} {
		for _, raw := range []string{"", "00112233445566778899aabbccddeeff"} {
			_, err := identity.NormalizeIdentifier(identity.IdentifierValue{Type: identity.TypeMachineID, Value: raw, Scope: scope})
			if !errors.Is(err, identity.ErrUnsupportedIdentifierFormat) {
				t.Fatalf("kind %v, value %q: %v", scope, raw, err)
			}
		}
	}
}

func TestNormalizeBIOSUUID(t *testing.T) {
	runTypeCases(t, identity.TypeBIOSUUID, nil, []typeCase{
		{name: "lower cased", raw: "4C4C4544-0042-3510-8054-B7C04F443232", want: "4c4c4544-0042-3510-8054-b7c04f443232"},
		{name: "braces are removed", raw: "{4c4c4544-0042-3510-8054-b7c04f443232}", want: "4c4c4544-0042-3510-8054-b7c04f443232"},
		{name: "without dashes", raw: "4c4c4544004235108054b7c04f443232", want: "4c4c4544-0042-3510-8054-b7c04f443232"},
		{name: "surrounding space is trimmed", raw: " 4c4c4544-0042-3510-8054-b7c04f443232\n", want: "4c4c4544-0042-3510-8054-b7c04f443232"},
		{name: "all zero", raw: "00000000-0000-0000-0000-000000000000", placeholder: true},
		{name: "all zero without dashes", raw: strings.Repeat("0", 32), placeholder: true},
		{name: "all f", raw: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", placeholder: true},
		{name: "board default", raw: "03000200-0400-0500-0006-000700080009", placeholder: true},
		{name: "oem text", raw: "To Be Filled By O.E.M.", err: identity.ErrInvalidIdentifierValue},
		{name: "hex where a dash belongs", raw: "4c4c4544a0042-3510-8054-b7c04f443232", err: identity.ErrInvalidIdentifierValue},
		{name: "dash in wrong place", raw: "4c4c454-40042-3510-8054-b7c04f443232", err: identity.ErrInvalidIdentifierValue},
		{name: "underscore separator", raw: "00112233_4455-6677-8899-aabbccddeeff", err: identity.ErrInvalidIdentifierValue},
		{name: "braces without dashes", raw: "{00112233445566778899aabbccddeeff}", err: identity.ErrInvalidIdentifierValue},
		{name: "not hex", raw: "4c4c4544-0042-3510-8054-b7c04f44323z", err: identity.ErrInvalidIdentifierValue},
		{name: "urn prefix", raw: "urn:uuid:00112233-4455-6677-8899-aabbccddeeff", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeIP(t *testing.T) {
	runTypeCases(t, identity.TypeIP, nil, []typeCase{
		{name: "ipv4", raw: "10.0.0.5", want: "10.0.0.5"},
		{name: "ipv4 documentation", raw: "192.0.2.1", want: "192.0.2.1"},
		{name: "ipv4 just below multicast", raw: "223.255.255.255", want: "223.255.255.255"},
		{name: "ipv4 just above loopback", raw: "128.0.0.1", want: "128.0.0.1"},
		{name: "ipv4 mapped in ipv6", raw: "::ffff:10.0.0.5", want: "10.0.0.5"},
		{name: "ipv4 mapped in hex", raw: "::FFFF:C000:201", want: "192.0.2.1"},
		{name: "ipv6 is compressed", raw: "2001:0DB8:0000::0001", want: "2001:db8::1"},
		{name: "ipv6 global", raw: "2a00:1450:4001:82b::200e", want: "2a00:1450:4001:82b::200e"},
		{name: "ipv6 zone is dropped", raw: "2001:db8::1%eth0", want: "2001:db8::1"},
		{name: "surrounding space is trimmed", raw: " 10.0.0.5\n", want: "10.0.0.5"},
		{name: "ipv4 unspecified", raw: "0.0.0.0", placeholder: true},
		{name: "ipv4 loopback", raw: "127.0.0.1", placeholder: true},
		{name: "ipv4 loopback range", raw: "127.10.0.1", placeholder: true},
		{name: "ipv4 link local", raw: "169.254.10.1", placeholder: true},
		{name: "ipv4 multicast", raw: "224.0.0.1", placeholder: true},
		{name: "ipv4 multicast upper bound", raw: "239.255.255.255", placeholder: true},
		{name: "ipv4 broadcast", raw: "255.255.255.255", placeholder: true},
		{name: "ipv4 loopback mapped in ipv6", raw: "::ffff:127.0.0.1", placeholder: true},
		{name: "ipv6 unspecified", raw: "0:0:0:0:0:0:0:0", placeholder: true},
		{name: "ipv6 loopback", raw: "::1", placeholder: true},
		{name: "ipv6 link local", raw: "FE80:0:0:0:0:0:0:1", placeholder: true},
		{name: "ipv6 link local with zone", raw: "fe80::1%eth0", placeholder: true},
		{name: "ipv6 multicast", raw: "FF02:0:0:0:0:0:0:1", placeholder: true},
		{name: "host name", raw: "web-01", err: identity.ErrInvalidIdentifierValue},
		{name: "cidr", raw: "10.0.0.0/24", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv6 cidr", raw: "::1/128", err: identity.ErrInvalidIdentifierValue},
		{name: "leading zero", raw: "010.0.0.1", err: identity.ErrInvalidIdentifierValue},
		{name: "octet out of range", raw: "256.0.0.1", err: identity.ErrInvalidIdentifierValue},
		{name: "short form", raw: "127.1", err: identity.ErrInvalidIdentifierValue},
		{name: "brackets", raw: "[::1]", err: identity.ErrInvalidIdentifierValue},
		{name: "with port", raw: "[2001:db8::1]:443", err: identity.ErrInvalidIdentifierValue},
		{name: "empty zone", raw: "2001:db8::1%", err: identity.ErrInvalidIdentifierValue},
		{name: "two zones", raw: "2001:db8::1%eth0%1", err: identity.ErrInvalidIdentifierValue},
		{name: "space in zone", raw: "2001:db8::1%eth 0", err: identity.ErrInvalidIdentifierValue},
		{name: "zone on ipv4", raw: "192.0.2.1%eth0", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeMAC(t *testing.T) {
	runTypeCases(t, identity.TypeMAC, nil, []typeCase{
		{name: "colons", raw: "3A:CD:30:CB:82:B5", want: "3a:cd:30:cb:82:b5"},
		{name: "dashes", raw: "3a-cd-30-cb-82-b5", want: "3a:cd:30:cb:82:b5"},
		{name: "dots", raw: "3acd.30cb.82b5", want: "3a:cd:30:cb:82:b5"},
		{name: "bare digits", raw: "3ACD30CB82B5", want: "3a:cd:30:cb:82:b5"},
		{name: "multicast is kept", raw: "01:00:5E:00:00:01", want: "01:00:5e:00:00:01"},
		{name: "surrounding space is trimmed", raw: "3a:cd:30:cb:82:b5 ", want: "3a:cd:30:cb:82:b5"},
		{name: "all zero", raw: "00:00:00:00:00:00", placeholder: true},
		{name: "all zero bare", raw: "000000000000", placeholder: true},
		{name: "broadcast", raw: "ff:ff:ff:ff:ff:ff", placeholder: true},
		{name: "broadcast bare", raw: "FFFFFFFFFFFF", placeholder: true},
		{name: "mixed separators", raw: "02:AB-CD:EF:01:23", err: identity.ErrInvalidIdentifierValue},
		{name: "short octet", raw: "2:ab:cd:ef:01:23", err: identity.ErrInvalidIdentifierValue},
		{name: "short dotted", raw: "02ab.cdef.123", err: identity.ErrInvalidIdentifierValue},
		{name: "eui-64", raw: "3a:cd:30:ff:fe:cb:82:b5", err: identity.ErrInvalidIdentifierValue},
		{name: "infiniband", raw: "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01", err: identity.ErrInvalidIdentifierValue},
		{name: "not hex", raw: "3a:cd:30:cb:82:zz", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeFQDN(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	runTypeCases(t, identity.TypeFQDN, nil, []typeCase{
		{name: "root dot and case", raw: "Web-01.Corp.Example.", want: "web-01.corp.example"},
		{name: "plain", raw: "Web.Example.ORG", want: "web.example.org"},
		{name: "underscore", raw: "_ldap.corp.example", want: "_ldap.corp.example"},
		{name: "underscore inside a label", raw: "web_01.corp.example", want: "web_01.corp.example"},
		{name: "digits in the first label", raw: "10-0-0-5.example.com", want: "10-0-0-5.example.com"},
		{name: "longest label", raw: label63 + ".example", want: label63 + ".example"},
		{name: "longest allowed", raw: strings.Repeat("a.", 126) + "a", want: strings.Repeat("a.", 126) + "a"},
		{name: "surrounding space is trimmed", raw: " web.example.org\n", want: "web.example.org"},
		{name: "placeholder", raw: "localhost.localdomain", placeholder: true},
		{name: "placeholder in upper case", raw: "LOCALHOST.LOCALDOMAIN.", placeholder: true},
		{name: "single label", raw: "web-01", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "single label with root dot", raw: "Example.", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "numeric last label", raw: "web.123", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv4", raw: "10.0.0.5", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv6", raw: "2001:db8::1", err: identity.ErrInvalidIdentifierValue},
		{name: "empty label", raw: "web..example", err: identity.ErrInvalidIdentifierValue},
		{name: "leading hyphen", raw: "-web.example", err: identity.ErrInvalidIdentifierValue},
		{name: "trailing hyphen", raw: "web-.example", err: identity.ErrInvalidIdentifierValue},
		{name: "label too long", raw: label63 + "a.example", err: identity.ErrInvalidIdentifierValue},
		{name: "too long", raw: strings.Repeat("a.", 127) + "a", err: identity.ErrInvalidIdentifierValue},
		{name: "space", raw: "web 01.example", err: identity.ErrInvalidIdentifierValue},
		{name: "wildcard", raw: "*.example.com", err: identity.ErrInvalidIdentifierValue},
		{name: "non ascii", raw: "ä.example", err: identity.ErrInvalidIdentifierValue},
		{name: "kelvin sign", raw: "Kube.example", err: identity.ErrInvalidIdentifierValue},
		{name: "escaped byte", raw: "a\\046b.example", err: identity.ErrInvalidIdentifierValue},
		{name: "root only", raw: ".", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeHostname(t *testing.T) {
	runTypeCases(t, identity.TypeHostname, nil, []typeCase{
		{name: "first label of an fqdn", raw: "WIN-NJAG2ND7ATT.corp.example", want: "win-njag2nd7att"},
		{name: "first label of an absolute fqdn", raw: "Web.Example.ORG.", want: "web"},
		{name: "single label", raw: " web-01 ", want: "web-01"},
		{name: "upper case", raw: "WEB", want: "web"},
		{name: "root dot", raw: "Example.", want: "example"},
		{name: "underscore", raw: "web_01", want: "web_01"},
		{name: "numeric label that is no ip", raw: "1234", want: "1234"},
		{name: "placeholder", raw: "localhost", placeholder: true},
		{name: "placeholder fqdn", raw: "localhost.localdomain", placeholder: true},
		{name: "placeholder in upper case", raw: "LOCALHOST", placeholder: true},
		{name: "ipv4", raw: "10.0.0.5", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv4 short form", raw: "127.1", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv4 with leading zero", raw: "192.168.1.010", err: identity.ErrInvalidIdentifierValue},
		{name: "ipv4 octet out of range", raw: "10.0.0.256", err: identity.ErrInvalidIdentifierValue},
		{name: "numeric last label", raw: "web.123", err: identity.ErrInvalidIdentifierValue},
		{name: "placeholder first label", raw: "localhost.corp.example", placeholder: true},
		{name: "ipv6", raw: "2001:db8::1", err: identity.ErrInvalidIdentifierValue},
		{name: "label too long", raw: strings.Repeat("a", 64), err: identity.ErrInvalidIdentifierValue},
		{name: "space", raw: "web 01", err: identity.ErrInvalidIdentifierValue},
		{name: "empty label", raw: "a..b", err: identity.ErrInvalidIdentifierValue},
		{name: "leading hyphen", raw: "-a.example", err: identity.ErrInvalidIdentifierValue},
		{name: "trailing hyphen", raw: "a-.example", err: identity.ErrInvalidIdentifierValue},
		{name: "wildcard", raw: "*.example", err: identity.ErrInvalidIdentifierValue},
		{name: "non ascii", raw: "ä.example", err: identity.ErrInvalidIdentifierValue},
		{name: "kelvin sign", raw: "Kube", err: identity.ErrInvalidIdentifierValue},
		{name: "root only", raw: ".", err: identity.ErrInvalidIdentifierValue},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeSSHHostKey(t *testing.T) {
	const ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	runTypeCases(t, identity.TypeSSHHostKey, nil, []typeCase{
		{name: "without comment", raw: ed25519, want: ed25519},
		{name: "comment is dropped", raw: ed25519 + " root@web-01", want: ed25519},
		{name: "extra spaces collapse", raw: "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl  ", want: ed25519},
		{name: "tab separated", raw: "ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\troot@web-01", want: ed25519},
		{name: "scanner port prefix", raw: "22 " + ed25519, want: ed25519},
		{name: "trailing line ends", raw: ed25519 + "\r\n\n", want: ed25519},
		{name: "truncated key", raw: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", err: identity.ErrInvalidIdentifierValue},
		{name: "key of another algorithm", raw: "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", err: identity.ErrInvalidIdentifierValue},
		{name: "two keys on two lines", raw: ed25519 + "\n" + ed25519, err: identity.ErrInvalidIdentifierValue},
		{name: "not base64", raw: "ssh-ed25519 not*base64", err: identity.ErrInvalidIdentifierValue},
		{name: "port zero", raw: "0 " + ed25519, err: identity.ErrInvalidIdentifierValue},
		{name: "type only", raw: "ssh-ed25519", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "upper case type", raw: "SSH-ED25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "certificate", raw: "ssh-ed25519-cert-v01@openssh.com AAAA", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "security key", raw: "sk-ssh-ed25519@openssh.com AAAAGnNr", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "dsa", raw: "ssh-dss AAAA", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "fingerprint is no key", raw: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "fingerprint after the type", raw: "ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "key without type", raw: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "unknown key type", raw: "pgp-key AAAAC3Nz", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "known hosts line", raw: "host " + ed25519, err: identity.ErrUnsupportedIdentifierFormat},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestNormalizeTLSPublicKeyHash(t *testing.T) {
	runTypeCases(t, identity.TypeTLSPublicKeyHash, nil, []typeCase{
		{name: "hash is lower cased", raw: "spki-sha256:" + strings.Repeat("AB", 32), want: "spki-sha256:" + strings.Repeat("ab", 32)},
		{name: "zero hash is a hash", raw: "spki-sha256:" + strings.Repeat("0", 64), want: "spki-sha256:" + strings.Repeat("0", 64)},
		{name: "surrounding space is trimmed", raw: "spki-sha256:" + strings.Repeat("a", 64) + "\n", want: "spki-sha256:" + strings.Repeat("a", 64)},
		{name: "empty digest", raw: "spki-sha256:", err: identity.ErrInvalidIdentifierValue},
		{name: "short digest", raw: "spki-sha256:" + strings.Repeat("a", 63), err: identity.ErrInvalidIdentifierValue},
		{name: "not hex", raw: "spki-sha256:" + strings.Repeat("g", 64), err: identity.ErrInvalidIdentifierValue},
		{name: "bare hex", raw: strings.Repeat("a", 64), err: identity.ErrUnsupportedIdentifierFormat},
		{name: "other scheme", raw: "cert-sha256:" + strings.Repeat("a", 64), err: identity.ErrUnsupportedIdentifierFormat},
		{name: "base64 digest", raw: "spki-sha256-base64:AAAA", err: identity.ErrUnsupportedIdentifierFormat},
		{name: "empty", raw: "", err: identity.ErrInvalidIdentifierValue},
	})
}

func TestEveryTypeHasANormalizer(t *testing.T) {
	types := []identity.IdentifierType{
		identity.TypeCloudIdentifier, identity.TypeGreenboneID, identity.TypeMachineID, identity.TypeBIOSUUID,
		identity.TypeAgentID, identity.TypeSSHHostKey, identity.TypeTLSPublicKeyHash, identity.TypeIP,
		identity.TypeFQDN, identity.TypeMAC, identity.TypeHostname,
	}
	for _, typ := range types {
		_, err := identity.NormalizeIdentifier(identity.IdentifierValue{Type: typ, Value: "x", Scope: linuxKind})
		if errors.Is(err, identity.ErrUnknownIdentifierType) {
			t.Fatalf("%s has no normalizer", typ)
		}
	}
	if _, err := identity.NormalizeIdentifier(identity.IdentifierValue{Type: "future_type", Value: "x"}); !errors.Is(err, identity.ErrUnknownIdentifierType) {
		t.Fatalf("unknown type accepted: %v", err)
	}
}

func TestDecideLeavesPlaceholdersOutButKeepsTheRest(t *testing.T) {
	mac := identity.IdentifierValue{Type: identity.TypeMAC, Value: "02:00:00:00:00:01"}
	loopback := identity.IdentifierValue{Type: identity.TypeIP, Value: "127.0.0.1"}
	zeroMAC := identity.IdentifierValue{Type: identity.TypeMAC, Value: "00:00:00:00:00:00"}
	observation := identity.Observation{Identifiers: []identity.IdentifierValue{loopback, zeroMAC, mac}}
	candidates := []identity.Candidate{
		{AssetKey: "shares only placeholders", Identifiers: []identity.IdentifierValue{loopback, zeroMAC}},
		{AssetKey: "shares the real mac", Identifiers: []identity.IdentifierValue{mac}},
	}
	got, err := identity.Decide(observation, candidates, identity.GreenboneMatchPolicy())
	if err != nil || got.Action != identity.ActionReuse || got.SelectedKey != "shares the real mac" || len(got.MergeIndices) != 0 {
		t.Fatalf("decision=%+v err=%v", got, err)
	}
	matches, err := identity.MatchingIdentifiers(observation.Identifiers, candidates[1].Identifiers)
	if err != nil || len(matches) != 1 || matches[0].Value != "02:00:00:00:00:01" {
		t.Fatalf("matches=%v err=%v", matches, err)
	}
	malformed := identity.IdentifierValue{Type: identity.TypeIP, Value: "not an ip"}
	if _, err := identity.Decide(identity.Observation{Identifiers: []identity.IdentifierValue{malformed, mac}}, candidates, identity.GreenboneMatchPolicy()); !errors.Is(err, identity.ErrInvalidIdentifierValue) {
		t.Fatalf("a malformed value must still fail the decision: %v", err)
	}
}
