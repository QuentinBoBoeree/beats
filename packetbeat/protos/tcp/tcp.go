// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package tcp

import (
	"bytes"
	"container/list"
	"fmt"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"
	"github.com/modern-go/concurrent"
	"sync"
	"time"
	"unicode"

	"github.com/elastic/beats/v7/packetbeat/flows"
	"github.com/elastic/beats/v7/packetbeat/protos"

	"github.com/tsg/gopacket/layers"
)

const TCPMaxDataInStream = 10 * (1 << 20)

const (
	TCPDirectionReverse  = 0
	TCPDirectionOriginal = 1
)

type SortedTCPPacket struct {
	pkt    *protos.Packet
	tcphdr *layers.TCP
}

//payload buffer (value in the list of unordered list)
type payload struct {
	tcphdr layers.TCP
	pkt    protos.Packet
	seq    uint32
}

type TCP struct {
	id           uint32
	streams      *common.Cache
	portMap      map[uint16]protos.Protocol
	protocols    protos.Protocols
	expiredConns expirationQueue
	messageTuple concurrent.Map
	statusTuple  concurrent.Map
	//待组装的连接缓存，用于没有FIN包的连接
	pendingAssembleConns *common.Cache
	expiredTuples        expirationTupleQueue
}

type expiredConnection struct {
	mod  protos.ExpirationAwareTCPPlugin
	conn *TCPConnection
}

type expiredTuple struct {
	tuple    *common.HashableIPPortTuple
	revTuple *common.HashableIPPortTuple
}

type expirationQueue struct {
	mutex sync.Mutex
	conns []expiredConnection
}

type expirationTupleQueue struct {
	mutex  sync.Mutex
	tuples []expiredTuple
}
type Processor interface {
	Process(flow *flows.FlowID, hdr *layers.TCP, pkt *protos.Packet)
}

var (
	droppedBecauseOfGaps = monitoring.NewInt(nil, "tcp.dropped_because_of_gaps")
)

type seqCompare int

const (
	seqLT seqCompare = -1
	seqEq seqCompare = 0
	seqGT seqCompare = 1
)

var (
	debugf  = logp.MakeDebug("tcp")
	isDebug = false
)

func (tcp *TCP) getID() uint32 {
	tcp.id++
	return tcp.id
}

func (tcp *TCP) decideProtocol(tuple *common.IPPortTuple) protos.Protocol {
	protocol, exists := tcp.portMap[tuple.SrcPort]
	if exists {
		return protocol
	}

	protocol, exists = tcp.portMap[tuple.DstPort]
	if exists {
		return protocol
	}

	return protos.UnknownProtocol
}

func (tcp *TCP) findStream(k common.HashableIPPortTuple) *TCPConnection {
	v := tcp.streams.Get(k)
	if v != nil {
		return v.(*TCPConnection)
	}
	return nil
}

type TCPConnection struct {
	id       uint32
	tuple    *common.IPPortTuple
	protocol protos.Protocol
	tcptuple common.TCPTuple
	tcp      *TCP

	lastSeq [2]uint32

	// protocols private data
	data protos.ProtocolData

	//temporary list for unordered packets
	alist [2]list.List
}

type TCPStream struct {
	conn *TCPConnection
	dir  uint8
}

func (conn *TCPConnection) String() string {
	return fmt.Sprintf("TcpStream id[%d] tuple[%s] protocol[%s] lastSeq[%d %d]",
		conn.id, conn.tuple, conn.protocol, conn.lastSeq[0], conn.lastSeq[1])
}

func (stream *TCPStream) addPacket(pkt *protos.Packet, tcphdr *layers.TCP) {
	conn := stream.conn
	mod := conn.tcp.protocols.GetTCP(conn.protocol)
	if mod == nil {
		if isDebug {
			protocol := conn.protocol
			debugf("Ignoring protocol for which we have no module loaded: %s",
				protocol)
		}
		return
	}

	if len(pkt.Payload) > 0 {
		conn.data = mod.Parse(pkt, &conn.tcptuple, stream.dir, conn.data)
	}

	if tcphdr.FIN {
		conn.data = mod.ReceivedFin(&conn.tcptuple, stream.dir, conn.data)
	}
}

func (stream *TCPStream) gapInStream(nbytes int) (drop bool) {
	conn := stream.conn
	mod := conn.tcp.protocols.GetTCP(conn.protocol)
	conn.data, drop = mod.GapInStream(&conn.tcptuple, stream.dir, nbytes, conn.data)
	return drop
}

//// Process if tcpLayer packets is disorder,need sorted them,otherwise will happend errors (unmatched request，unmatched response,capture loss packet)
//func (tcp *TCP) Process(id *flows.FlowID, tcphdr *layers.TCP, pkt *protos.Packet) {
//	//对过期的tuple进行通知，触发清理操作
//	tcp.expiredTuples.notifyAll(tcp)
//	//首先缓存tuple
//	tcp.cacheTuple(pkt)
//	//if packet len is not empty,push it to map<tuple,list<packet>>
//	if len(pkt.Payload) > 0 {
//		sortedTCPPackets, contains := tcp.messageTuple.Load(pkt.Tuple.Hashable())
//		if !contains || sortedTCPPackets == nil {
//			sortedTCPPackets = list.New()
//		}
//		//deep copy
//		preSortedPkt := new(protos.Packet)
//		preSortedTcphdr := new(layers.TCP)
//		*preSortedPkt = *pkt
//		*preSortedTcphdr = *tcphdr
//		tcpPacket := SortedTCPPacket{pkt: preSortedPkt, tcphdr: preSortedTcphdr}
//		sortedPacketList := sortedTCPPackets.(*list.List)
//		sortedPacketList.PushBack(&tcpPacket)
//		tcp.messageTuple.Store(pkt.Tuple.Hashable(), sortedPacketList)
//	}
//	//if tcplayer packet set is FIN,
//	//pop specify Tuple packets,
//	//sorted disorder packets,
//	//process origin assemble packets function
//	//todo gap 2 min where FIN packet received
//	//todo if transaction is expired,need expired packet
//	if tcphdr.FIN || tcphdr.RST {
//		finished, tupleExist := tcp.statusTuple.Load(pkt.Tuple.Hashable())
//		if !tupleExist || finished == nil || finished.(bool) == false {
//			tcp.statusTuple.Store(pkt.Tuple.Hashable(), true)
//			tcp.statusTuple.Store(pkt.Tuple.RevHashable(), true)
//		} else {
//			return
//		}
//		//从map中取出请求tcp、packet结构体
//		directionTCPPackets, contains := tcp.messageTuple.LoadAndDelete(pkt.Tuple.Hashable())
//		negativeDirectionTCPPackets, negativeContains := tcp.messageTuple.LoadAndDelete(pkt.Tuple.RevHashable())
//		if !contains && !negativeContains {
//			return
//		}
//		if contains && !negativeContains {
//			tcp.handleTCPPackets(id, directionTCPPackets)
//			return
//		}
//		if !contains && negativeContains {
//			tcp.handleTCPPackets(id, negativeDirectionTCPPackets)
//			return
//		}
//		sortedPacketList := directionTCPPackets.(*list.List)
//		if sortedPacketList != nil && sortedPacketList.Len() > 0 {
//			isRequest, isResponse := tcp.judgeHttpDirection(sortedPacketList.Front().Value.(*SortedTCPPacket).pkt)
//			if isRequest {
//				logp.Info("--------detected request--------")
//				tcp.handleTCPPackets(id, directionTCPPackets)
//				tcp.handleTCPPackets(id, negativeDirectionTCPPackets)
//			} else if isResponse {
//				logp.Info("--------detected response--------")
//				tcp.handleTCPPackets(id, negativeDirectionTCPPackets)
//				tcp.handleTCPPackets(id, directionTCPPackets)
//			}
//		}
//
//		tcp.ProcessSortedPacket(id, tcphdr, pkt)
//		tcp.statusTuple.Delete(pkt.Tuple.Hashable())
//		tcp.statusTuple.Delete(pkt.Tuple.RevHashable())
//		return
//	}
//}

var (
	constHTTPVersion = []byte("HTTP/")
)

func (tcp *TCP) judgeHttpDirection(pkt *protos.Packet) (request, response bool) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return false, false
	}
	i := bytes.Index(pkt.Payload, []byte("\r\n"))
	if i == -1 {
		return false, false
	}
	var isRequest = false
	var isResponse = false
	fline := pkt.Payload[0:i]
	if bytes.Equal(pkt.Payload[0:5], constHTTPVersion) {
		//RESPONSE
		isResponse = true
	} else {
		// REQUEST
		afterMethodIdx := bytes.IndexFunc(fline, unicode.IsSpace)
		afterRequestURIIdx := bytes.LastIndexFunc(fline, unicode.IsSpace)

		// Make sure we have the VERB + URI + HTTP_VERSION
		if afterMethodIdx == -1 || afterRequestURIIdx == -1 || afterMethodIdx == afterRequestURIIdx {
			return false, false
		}

		versionIdx := afterRequestURIIdx + len(constHTTPVersion) + 1
		if len(fline) > versionIdx && bytes.Equal(fline[afterRequestURIIdx+1:versionIdx], constHTTPVersion) {
			isRequest = true
		}
	}
	return isRequest, isResponse
}

//func (tcp *TCP) handleTCPPackets(id *flows.FlowID, packets interface{}) {
//	sortedPacketList := packets.(*list.List)
//	if sortedPacketList == nil || sortedPacketList.Len() == 0 {
//		return
//	}
//	sortList := Sort(sortedPacketList)
//	for p := sortList.Front(); p != nil; p = p.Next() {
//		content, err := json.Marshal(p.Value.(*SortedTCPPacket).tcphdr)
//		if err != nil {
//			logp.Info("marshall error:%s", err)
//		}
//		logp.Info("tcp包:%s----", string(content))
//		tcp.ProcessSortedPacket(id, p.Value.(*SortedTCPPacket).tcphdr, p.Value.(*SortedTCPPacket).pkt)
//	}
//}

func (tcp *TCP) Process(id *flows.FlowID, tcphdr *layers.TCP, pkt *protos.Packet) {
	defer logp.Recover("Process tcp exception")

	tcp.expiredConns.notifyAll()

	stream, created := tcp.getStream(pkt)
	if stream.conn == nil {
		return
	}

	conn := stream.conn
	if id != nil {
		id.AddConnectionID(uint64(conn.id))
	}
	if len(pkt.Payload) == 0 && !tcphdr.FIN {
		// return early if packet is not interesting. Still need to find/create
		// stream first in order to update the TCP stream timer
		return
	}
	tcpStartSeq := tcphdr.Seq
	tcpSeq := tcpStartSeq + uint32(len(pkt.Payload))
	lastSeq := conn.lastSeq[stream.dir]
	if isDebug {
		debugf("pkt.start_seq=%v pkt.last_seq=%v stream.last_seq=%v (len=%d)",
			tcpStartSeq, tcpSeq, lastSeq, len(pkt.Payload))
	}
	if len(pkt.Payload) > 0 && lastSeq != 0 {
		if tcpSeqBeforeEq(tcpSeq, lastSeq) {
			if isDebug {
				debugf("Ignoring retransmitted segment. pkt.seq=%v len=%v stream.seq=%v",
					tcphdr.Seq, len(pkt.Payload), lastSeq)
			}
			return
		}

		switch tcpSeqCompare(lastSeq, tcpStartSeq) {
		case seqLT: // lastSeq < tcpStartSeq => Gap in tcp stream detected
			if created {
				break
			}
			//add out of order packets to buffer alist
			buffer := &payload{
				tcphdr: *tcphdr,
				pkt:    *pkt,
				seq:    tcpStartSeq,
			}
			logp.Info("---detected gap---")
			insertUnordered(&conn.alist[stream.dir], buffer)
			return

		case seqGT:
			// lastSeq > tcpStartSeq => overlapping TCP segment detected. shrink packet
			//如果上一个包的序号大于当前包的序号，则说明两个包之间有重叠
			delta := lastSeq - tcpStartSeq

			if isDebug {
				debugf("Overlapping tcp segment. last_seq %d, seq: %d, delta: %d",
					lastSeq, tcpStartSeq, delta)
			}

			pkt.Payload = pkt.Payload[delta:]
			tcphdr.Seq += delta
		}
	}

	if len(pkt.Payload) > 0 || tcphdr.FIN {
		conn.lastSeq[stream.dir] = tcpSeq
		stream.addPacket(pkt, tcphdr)
	}
	//iterate through list till we hit upon next gap
	for e := conn.alist[stream.dir].Front(); e != nil; {
		logp.Info("iterate through list till we hit upon next gap")
		nexte := e.Next()
		unOrderedPayload := e.Value.(*payload)
		if unOrderedPayload.seq < conn.lastSeq[stream.dir] {
			conn.alist[stream.dir].Remove(e)
			//Dropping old pkts
		} else if unOrderedPayload.seq == conn.lastSeq[stream.dir] {
			logp.Info("reorder operation")
			tcphdr1 := &unOrderedPayload.tcphdr
			pkt1 := &unOrderedPayload.pkt
			conn.alist[stream.dir].Remove(e)
			tcpStartSeq = tcphdr1.Seq
			tcpSeq = tcpStartSeq + uint32(len(pkt1.Payload))
			conn.lastSeq[stream.dir] = tcpSeq
			stream.addPacket(pkt1, tcphdr1)
		} else {
			break
		}
		e = nexte
	}
	// FIN包、RST包作为终止条件，如果中间出现丢包，则需要在此处flush一下缓存
	if tcphdr.FIN || tcphdr.RST {
		logp.Info("flush buffer list")
		if len(conn.alist) == 0 {
			return
		}
		for e := conn.alist[0].Front(); e != nil; {
			nexte := e.Next()
			buf := e.Value.(*payload)
			if buf == nil {
				continue
			}
			stream.addPacket(&buf.pkt, &buf.tcphdr)
			conn.alist[0].Remove(e)
			e = nexte
		}
		for e := conn.alist[1].Front(); e != nil; {
			nexte := e.Next()
			buf := e.Value.(*payload)
			if buf == nil {
				continue
			}
			stream.addPacket(&buf.pkt, &buf.tcphdr)
			conn.alist[1].Remove(e)
			e = nexte
		}
		return
	}
}

//insert unordered packets in sorted linked list so that it can behave as a queue
func insertUnordered(l *list.List, buffer *payload) {
	if l.Len() == 0 {
		l.PushFront(buffer)
		return
	}
	for e := l.Front(); e != nil; e = e.Next() {
		buf := e.Value.(*payload)
		if buf.seq > buffer.seq {
			l.InsertBefore(buffer, e)
			return
		}
	}
	l.PushBack(buffer)
	return
}

// Sort sort arithmetic should be optimized
func Sort(oldList *list.List) (newList *list.List) {
	newList = list.New()

	//用老链表进行遍历 与新链表进行表

	for v := oldList.Front(); v != nil; v = v.Next() {
		node := newList.Front()

		for nil != node {
			//seq compare
			if node.Value.(*SortedTCPPacket).pkt.Seq > v.Value.(*SortedTCPPacket).pkt.Seq {
				//InsertBefore
				newList.InsertBefore(v.Value.(*SortedTCPPacket), node)
				break
			} else if node.Value.(*SortedTCPPacket).pkt.Seq == v.Value.(*SortedTCPPacket).pkt.Seq {
				//ack compare
				if node.Value.(*SortedTCPPacket).pkt.Seq > v.Value.(*SortedTCPPacket).pkt.Seq {
					newList.InsertBefore(v.Value.(*SortedTCPPacket), node)
					break
				}
			}
			//assign next node
			node = node.Next()
		}
		if node == nil {
			newList.PushBack(v.Value.(*SortedTCPPacket))
		}
	}
	return newList
}

func (tcp *TCP) getStream(pkt *protos.Packet) (stream TCPStream, created bool) {
	if conn := tcp.findStream(pkt.Tuple.Hashable()); conn != nil {
		return TCPStream{conn: conn, dir: TCPDirectionOriginal}, false
	}

	if conn := tcp.findStream(pkt.Tuple.RevHashable()); conn != nil {
		return TCPStream{conn: conn, dir: TCPDirectionReverse}, false
	}

	protocol := tcp.decideProtocol(&pkt.Tuple)
	if protocol == protos.UnknownProtocol {
		// don't follow
		return TCPStream{}, false
	}

	var timeout time.Duration
	mod := tcp.protocols.GetTCP(protocol)
	if mod != nil {
		timeout = mod.ConnectionTimeout()
	}

	if isDebug {
		t := pkt.Tuple
		debugf("Connection src[%s:%d] dst[%s:%d] doesn't exist, creating new",
			t.SrcIP.String(), t.SrcPort,
			t.DstIP.String(), t.DstPort)
	}

	conn := &TCPConnection{
		id:       tcp.getID(),
		tuple:    &pkt.Tuple,
		protocol: protocol,
		tcp:      tcp}
	conn.tcptuple = common.TCPTupleFromIPPort(conn.tuple, conn.id)
	tcp.streams.PutWithTimeout(pkt.Tuple.Hashable(), conn, timeout)
	return TCPStream{conn: conn, dir: TCPDirectionOriginal}, true
}

func tcpSeqCompare(seq1, seq2 uint32) seqCompare {
	i := int32(seq1 - seq2)
	switch {
	case i == 0:
		return seqEq
	case i < 0:
		return seqLT
	default:
		return seqGT
	}
}

func tcpSeqBefore(seq1 uint32, seq2 uint32) bool {
	return int32(seq1-seq2) < 0
}

func tcpSeqBeforeEq(seq1 uint32, seq2 uint32) bool {
	return int32(seq1-seq2) <= 0
}

func buildPortsMap(plugins map[protos.Protocol]protos.TCPPlugin) (map[uint16]protos.Protocol, error) {
	var res = map[uint16]protos.Protocol{}

	for proto, protoPlugin := range plugins {
		for _, port := range protoPlugin.GetPorts() {
			oldProto, exists := res[uint16(port)]
			if exists {
				if oldProto == proto {
					continue
				}
				return nil, fmt.Errorf("Duplicate port (%d) exists in %s and %s protocols",
					port, oldProto, proto)
			}
			res[uint16(port)] = proto
		}
	}

	return res, nil
}

// Creates and returns a new Tcp.
func NewTCP(p protos.Protocols) (*TCP, error) {
	isDebug = logp.IsDebug("tcp")

	portMap, err := buildPortsMap(p.GetAllTCP())
	if err != nil {
		return nil, err
	}

	tcp := &TCP{
		protocols: p,
		portMap:   portMap,
	}
	tcp.streams = common.NewCacheWithRemovalListener(
		protos.DefaultTransactionExpiration,
		protos.DefaultTransactionHashSize,
		tcp.removalListener)

	tcp.streams.StartJanitor(protos.DefaultTransactionExpiration)
	if isDebug {
		debugf("tcp", "Port map: %v", portMap)
	}

	return tcp, nil
}

func (tcp *TCP) removalListener(_ common.Key, value common.Value) {
	conn := value.(*TCPConnection)
	mod := conn.tcp.protocols.GetTCP(conn.protocol)
	if mod != nil {
		awareMod, ok := mod.(protos.ExpirationAwareTCPPlugin)
		if ok {
			tcp.expiredConns.add(awareMod, conn)
		}
	}
}

func (ec *expiredConnection) notify() {
	ec.mod.Expired(&ec.conn.tcptuple, ec.conn.data)
	if len(ec.conn.alist) == 0 {
		return
	}
	payloadElement := ec.conn.alist[0].Front()
	if payloadElement == nil {
		payloadElement = ec.conn.alist[1].Front()
	}
	if payloadElement == nil {
		return
	}
	buf := payloadElement.Value.(*payload)
	stream, created := ec.conn.tcp.getStream(&buf.pkt)
	logp.Info("detected expiredConnection stream has packet buffer")
	if created {
		if isDebug {
			debugf("detected expiredConnection stream created")
		}
	}
	if stream.conn == nil {
		return
	}
	for e := ec.conn.alist[0].Front(); e != nil; {
		nexte := e.Next()
		buf := e.Value.(*payload)
		if buf == nil {
			continue
		}
		stream.addPacket(&buf.pkt, &buf.tcphdr)
		ec.conn.alist[0].Remove(e)
		e = nexte
	}
	for e := ec.conn.alist[1].Front(); e != nil; {
		nexte := e.Next()
		buf := e.Value.(*payload)
		if buf == nil {
			continue
		}
		stream.addPacket(&buf.pkt, &buf.tcphdr)
		ec.conn.alist[0].Remove(e)
		e = nexte
	}

}

func (eq *expirationQueue) add(mod protos.ExpirationAwareTCPPlugin, conn *TCPConnection) {
	eq.mutex.Lock()
	eq.conns = append(eq.conns, expiredConnection{
		mod:  mod,
		conn: conn,
	})
	eq.mutex.Unlock()
}

func (eq *expirationQueue) getExpired() (conns []expiredConnection) {
	eq.mutex.Lock()
	conns, eq.conns = eq.conns, nil
	eq.mutex.Unlock()
	return conns
}

func (eq *expirationQueue) notifyAll() {
	for _, expiration := range eq.getExpired() {
		expiration.notify()
	}
}
