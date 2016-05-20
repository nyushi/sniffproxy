package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	m sync.Mutex

	snapshot_len int32
	promiscuous  bool = true
	err          error
	timeout      time.Duration = 5 * time.Second
	handle       *pcap.Handle

	pktq      = map[string]net.Conn{}
	wrote     = map[string]int{}
	packets   = map[string]map[int]*layers.TCP{}
	captureIF = flag.String("i", "lo", "name of capture interface")
	to        = flag.String("to", "127.0.0.1:8080", "target address and port")
	filter    = flag.String("filter", "tcp and dst port 80", "pcap filter for capturing")
	buffer    = flag.Int("buffer", 10, "buffer size(Mbytes)")
)

func main() {
	flag.Parse()

	inactive, err := pcap.NewInactiveHandle(*captureIF)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(65535 * 2); err != nil {
		return
	}
	if err = inactive.SetTimeout(timeout); err != nil {
		return
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return
	}

	if err = inactive.SetBufferSize(*buffer * 1024 * 1024); err != nil {
		return
	}
	handle, err = inactive.Activate()
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("start capture and proxy: i=%s, to=%s, filter=%s, buffer=%dM", *captureIF, *to, *filter, *buffer)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		dropCount := 0
		for {
			m.Lock()
			st, _ := handle.Stats()
			if st != nil {
				if dropCount < st.PacketsDropped {
					log.Printf("%d packet dropped. please renice or increase buffer size.", st.PacketsDropped-dropCount)
					dropCount = st.PacketsDropped
				}
			}
			m.Unlock()
			time.Sleep(5 * time.Second)
		}
	}()
	for packet := range packetSource.Packets() {
		m.Lock()
		processPacket(packet)
		m.Unlock()
	}
}

func processPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort := tcp.SrcPort.String()

		if _, ok := packets[srcPort]; !ok {
			packets[srcPort] = map[int]*layers.TCP{}
		}
		packets[srcPort][int(tcp.Seq)] = tcp

		if tcp.FIN {
			seqs := packets[srcPort]
			delete(packets, srcPort)

			log.Printf("proceed connection: srcPort=%s", srcPort)

			go func(seqs map[int]*layers.TCP) {

				var keys = []int{}
				for k := range seqs {
					keys = append(keys, k)
				}
				sort.Ints(keys)

				conn, err := net.Dial("tcp", *to)
				if err != nil {
					log.Println(err)
					return
				}

				for _, seq := range keys {
					p := seqs[seq]
					conn.Write(p.Payload)
				}

				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					log.Println(err)
				}

				ioutil.ReadAll(conn)
				conn.Close()
			}(seqs)
		}
	}
}
