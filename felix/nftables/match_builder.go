// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"fmt"
	"math/bits"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
)

type MatchCriteria []string

func Match() MatchCriteria {
	return nil
}

func (m MatchCriteria) Render() string {
	return strings.Join([]string(m), " ")
}

func (m MatchCriteria) String() string {
	return fmt.Sprintf("MatchCriteria[%s]", m.Render())
}

func (m MatchCriteria) MarkClear(mark uint32) MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("meta mark & %#x == 0", mark))
}

func (m MatchCriteria) MarkNotClear(mark uint32) MatchCriteria {
	if mark == 0 {
		log.Panic("Probably bug: zero mark")
	}
	return append(m, fmt.Sprintf("meta mark & %#x != 0", mark))
}

func (m MatchCriteria) MarkSingleBitSet(mark uint32) MatchCriteria {
	if bits.OnesCount32(mark) != 1 {
		// Disallow multi-bit matches to force user to think about the mask they should use.
		// For example, if you are storing a number in the mark then you likely want to match on its
		// 0-bits too
		log.WithField("mark", mark).Panic("MarkSingleBitSet() should only be used with a single mark bit")
	}
	return m.MarkMatchesWithMask(mark, mark)
}

func (m MatchCriteria) MarkMatchesWithMask(mark, mask uint32) MatchCriteria {
	logCxt := log.WithFields(log.Fields{
		"mark": mark,
		"mask": mask,
	})
	if mask == 0 {
		logCxt.Panic("Bug: mask is 0.")
	}
	if mark&mask != mark {
		logCxt.Panic("Bug: mark is not contained in mask")
	}
	return append(m, fmt.Sprintf("meta mark & %#x == %#x", mask, mark))
}

func (m MatchCriteria) NotMarkMatchesWithMask(mark, mask uint32) MatchCriteria {
	logCxt := log.WithFields(log.Fields{
		"mark": mark,
		"mask": mask,
	})
	if mask == 0 {
		logCxt.Panic("Bug: mask is 0.")
	}
	if mark&mask != mark {
		logCxt.Panic("Bug: mark is not contained in mask")
	}
	return append(m, fmt.Sprintf("meta mark & %#x != %#x", mask, mark))
}

func (m MatchCriteria) InInterface(ifaceMatch string) MatchCriteria {
	return append(m, fmt.Sprintf("iifname %s", ifaceMatch))
}

func (m MatchCriteria) OutInterface(ifaceMatch string) MatchCriteria {
	return append(m, fmt.Sprintf("oifname %s", ifaceMatch))
}

func (m MatchCriteria) RPFCheckPassed(acceptLocal bool) MatchCriteria {
	// TODO: CASEY
	ret := append(m, "-m rpfilter --validmark")
	if acceptLocal {
		ret = append(ret, "--accept-local")
	}
	return ret
}

func (m MatchCriteria) RPFCheckFailed(acceptLocal bool) MatchCriteria {
	// TODO: CASEY - is this right?
	// https://wiki.nftables.org/wiki-nftables/index.php/Matching_routing_information
	ret := append(m, "fib saddr . iif oif eq 0")
	if acceptLocal {
		// ret = append(ret, "--accept-local")
	}
	return ret
}

func (m MatchCriteria) IPVSConnection() MatchCriteria {
	// TODO: CASEY
	// return append(m, "-m ipvs --ipvs")
	panic("IPVS not supported in nftables mode")
}

func (m MatchCriteria) NotIPVSConnection() MatchCriteria {
	// TODO: CASEY
	// return append(m, "-m ipvs ! --ipvs")
	panic("IPVS not supported in nftables mode")
}

type AddrType string

const (
	AddrTypeLocal AddrType = "local"
)

func (m MatchCriteria) NotSrcAddrType(addrType AddrType, limitIfaceOut bool) MatchCriteria {
	if limitIfaceOut {
		// TODO CASEY
		// return append(m, fmt.Sprintf("-m addrtype ! --src-type %s --limit-iface-out", addrType))
		return append(m, fmt.Sprintf("fib daddr type != %s", addrType))
	} else {
		return append(m, fmt.Sprintf("fib daddr type != %s", addrType))
	}
}

func (m MatchCriteria) SrcAddrType(addrType AddrType, limitIfaceOut bool) MatchCriteria {
	if limitIfaceOut {
		// TODO CASEY
		// return append(m, fmt.Sprintf("-m addrtype --src-type %s --limit-iface-out", addrType))
		return append(m, fmt.Sprintf("fib saddr type != %s", addrType))
	} else {
		return append(m, fmt.Sprintf("fib saddr type != %s", addrType))
	}
}

func (m MatchCriteria) DestAddrType(addrType AddrType) MatchCriteria {
	return append(m, fmt.Sprintf("fib daddr type %s", addrType))
}

func (m MatchCriteria) NotDestAddrType(addrType AddrType) MatchCriteria {
	return append(m, fmt.Sprintf("fib daddr type != %s", addrType))
}

func (m MatchCriteria) ConntrackStatus(statusNames string) MatchCriteria {
	return append(m, fmt.Sprintf("ct status %s", strings.ToLower(statusNames)))
}

func (m MatchCriteria) NotConntrackStatus(statusNames string) MatchCriteria {
	return append(m, fmt.Sprintf("ct status != %s", strings.ToLower(statusNames)))
}

func (m MatchCriteria) ConntrackState(stateNames string) MatchCriteria {
	return append(m, fmt.Sprintf("ct state %s", strings.ToLower(stateNames)))
}

func (m MatchCriteria) NotConntrackState(stateNames string) MatchCriteria {
	return append(m, fmt.Sprintf("ct state != %s", strings.ToLower(stateNames)))
}

func (m MatchCriteria) Protocol(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol %s", name))
}

func (m MatchCriteria) NotProtocol(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol != %s", name))
}

func (m MatchCriteria) ProtocolNum(num uint8) MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol %d", num))
}

func (m MatchCriteria) NotProtocolNum(num uint8) MatchCriteria {
	return append(m, fmt.Sprintf("ip protocol != %d", num))
}

func (m MatchCriteria) SourceNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr %s", net))
}

func (m MatchCriteria) NotSourceNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr != %s", net))
}

func (m MatchCriteria) DestNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr %s", net))
}

func (m MatchCriteria) NotDestNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr != %s", net))
}

func (m MatchCriteria) SourceIPSet(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr @%s", name))
}

func (m MatchCriteria) NotSourceIPSet(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip saddr != @%s", name))
}

func (m MatchCriteria) SourceIPPortSet(name string) MatchCriteria {
	// TODO: CASEY: Does this do the right thing?
	return append(m, fmt.Sprintf("ip saddr @%s tcp sport @%s", name, name))
}

func (m MatchCriteria) NotSourceIPPortSet(name string) MatchCriteria {
	// TODO: CASEY: Does this do the right thing?
	return append(m, fmt.Sprintf("ip saddr != @%s tcp sport != @%s", name, name))
}

func (m MatchCriteria) DestIPSet(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr @%s", name))
}

func (m MatchCriteria) NotDestIPSet(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip daddr != @%s", name))
}

func (m MatchCriteria) DestIPPortSet(name string) MatchCriteria {
	// TODO: CASEY: Does this do the right thing?
	return append(m, fmt.Sprintf("ip daddr @%s tcp dport @%s", name, name))
}

func (m MatchCriteria) NotDestIPPortSet(name string) MatchCriteria {
	// TODO: CASEY: Does this do the right thing?
	return append(m, fmt.Sprintf("ip daddr != @%s tcp dport != @%s", name, name))
}

func (m MatchCriteria) IPSetNames() (ipSetNames []string) {
	// TODO: CASEY: Where is this used?
	for _, matchString := range []string(m) {
		words := strings.Split(matchString, " ")
		for i := range words {
			if words[i] == "--match-set" && (i+1) < len(words) {
				ipSetNames = append(ipSetNames, words[i+1])
			}
		}
	}
	return
}

func (m MatchCriteria) SourcePorts(ports ...uint16) MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport %s", portsString))
}

func (m MatchCriteria) NotSourcePorts(ports ...uint16) MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport != %s", portsString))
}

func (m MatchCriteria) DestPorts(ports ...uint16) MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport %s", portsString))
}

func (m MatchCriteria) NotDestPorts(ports ...uint16) MatchCriteria {
	portsString := PortsToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport != %s", portsString))
}

func (m MatchCriteria) SourcePortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport %s", portsString))
}

func (m MatchCriteria) NotSourcePortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp sport != %s", portsString))
}

func (m MatchCriteria) DestPortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport %s", portsString))
}

func (m MatchCriteria) NotDestPortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("tcp dport != %s", portsString))
}

func (m MatchCriteria) ICMPType(t uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d", t))
}

func (m MatchCriteria) NotICMPType(t uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type != %d", t))
}

func (m MatchCriteria) ICMPTypeAndCode(t, c uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d code %d", t, c))
}

func (m MatchCriteria) NotICMPTypeAndCode(t, c uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type !=%d code !=%d", t, c))
}

func (m MatchCriteria) ICMPV6Type(t uint8) MatchCriteria {
	// CASEY: TODO: Is this right?
	return append(m, fmt.Sprintf("icmp type %d", t))
}

func (m MatchCriteria) NotICMPV6Type(t uint8) MatchCriteria {
	// CASEY: TODO: Is this right?
	return append(m, fmt.Sprintf("icmp type != %d", t))
}

func (m MatchCriteria) ICMPV6TypeAndCode(t, c uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type %d code %d", t, c))
}

func (m MatchCriteria) NotICMPV6TypeAndCode(t, c uint8) MatchCriteria {
	return append(m, fmt.Sprintf("icmp type != %d code != %d", t, c))
}

// VXLANVNI matches on the VNI contained within the VXLAN header.  It assumes that this is indeed a VXLAN
// packet; i.e. it should be used with a protocol==UDP and port==VXLAN port match.
//
// Note: the -m u32 option is not supported on iptables in NFT mode.
// https://wiki.nftables.org/wiki-nftables/index.php/Supported_features_compared_to_xtables#u32
func (m MatchCriteria) VXLANVNI(vni uint32) MatchCriteria {
	// This uses the U32 module, a simple VM for extracting bytes from a packet.  See
	// http://www.stearns.org/doc/iptables-u32.current.html
	// return append(m, fmt.Sprintf(`-m u32 --u32 "`+
	// 	`0>>22&0x3C@` /* jump over the IP header */ +
	// 	`12>>8=0x%x` /* skip over 8 bytes of UDP header and 4 of VXLAN and compare 3 bytes with the expected VNI */ +
	// 	`"`, vni))
	// TODO: CASEY: Implement this.
	return m
}

// Converts a list of ports to a multiport set suitable for inline use in nftables rules.
func PortsToMultiport(ports []uint16) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		portFragments[i] = fmt.Sprintf("%d", port)
	}
	portsString := strings.Join(portFragments, ", ")
	return fmt.Sprintf("{ %s }", portsString)
}

func PortRangesToMultiport(ports []*proto.PortRange) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		if port.First == port.Last {
			portFragments[i] = fmt.Sprintf("%d", port.First)
		} else {
			portFragments[i] = fmt.Sprintf("%d-%d", port.First, port.Last)
		}
	}
	portsString := strings.Join(portFragments, ", ")
	return fmt.Sprintf("{ %s }", portsString)
}
