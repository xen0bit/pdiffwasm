// +build js,wasm

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"syscall/js"

	"github.com/ekzhu/counter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	udpLayer layers.UDP
	tcpLayer layers.TCP
	payload  gopacket.Payload

	cachedPackets = make(map[int][]byte)
	//extracted defaults from pdiff

	//Minimum payload length for a packet to be parsed
	//handled
	minLength = 2
	//Default number of bytes to list in comparison
	maxComp = 10
	//Default number of packet lengths to list in comparison
	numLengths = 20
	//How many bytes to look at in each payload
	bRange = 30
)

//Used for sorting frequency analysis
type Pair struct {
	Key   int
	Value int
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }

//golang error patterns in js are something else huh?
func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

func printPcap(this js.Value, inputs []js.Value) interface{} {
	binArr := inputs[0]
	callback := inputs[len(inputs)-1:][0]
	//options := inputs[1].String()
	inBuf := make([]uint8, binArr.Get("byteLength").Int())
	js.CopyBytesToGo(inBuf, binArr)
	r := bytes.NewReader(inBuf)
	pr, err := pcapgo.NewReader(r)
	check(err)
	packetCount := 0
	for {
		//fmt.Println("PacketNum:", packetCount)
		packetCount++
		packetData, _, err := pr.ReadPacketData()
		if err != io.EOF {
			check(err)
		} else {
			break
		}

		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&udpLayer,
			&tcpLayer,
			&payload,
		)

		foundLayerTypes := []gopacket.LayerType{}
		errr := parser.DecodeLayers(packetData, &foundLayerTypes)
		if errr != nil {
			fmt.Println("Trouble decoding layers: ", err)
		} else {
			var ipSrc string
			var ipDst string
			var tcpSrc string
			var tcpDst string
			var udpSrc string
			var udpDst string
			var payloadHex string
			for _, layerType := range foundLayerTypes {

				if layerType == layers.LayerTypeIPv4 {
					//fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
					ipSrc = ipLayer.SrcIP.String()
					ipDst = ipLayer.DstIP.String()
				}
				if layerType == layers.LayerTypeTCP {
					//fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
					//fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
					tcpSrc = tcpLayer.SrcPort.String()
					tcpDst = tcpLayer.DstPort.String()
				}
				if layerType == layers.LayerTypeUDP {
					//fmt.Println("UDP Port: ", udpLayer.SrcPort, "->", udpLayer.DstPort)
					udpSrc = udpLayer.SrcPort.String()
					udpDst = udpLayer.DstPort.String()
				}
			}
			payloadHex = hex.Dump(payload.LayerContents())
			//fmt.Println("Payload:")
			//fmt.Println(hex.Dump(payload.LayerContents()))
			//Build the cached packets object
			cachedPackets[packetCount] = payload.LayerContents()
			//fmt.Println(cachedPackets[packetCount])
			callback.Invoke(js.Null(), packetCount, ipSrc, ipDst, tcpSrc, tcpDst, udpSrc, udpDst, payloadHex)
		}
	}
	callback.Invoke("Complete")
	return 1
}

func filterCachedPackets(neededIds []int) map[int][]byte {
	out := make(map[int][]byte)
	for _, v := range neededIds {
		//Check that the packetid exists in the list of pre-filtered id's generated from the GUI
		cachedValue, exists := cachedPackets[v]
		if exists {
			//Misc conditions
			if len(cachedValue) > minLength {
				out[v] = cachedValue
			}
		}
	}
	return out
}

func listCommon(packets map[int][]byte) string {
	outstring := ""
	for packetIterator := 0; packetIterator <= bRange; packetIterator++ {
		packetCounter := counter.NewCounter()
		totalPackets := 0
		//Populate the counter
		for _, v := range packets {
			//fmt.Println("length: " + strconv.Itoa(len(v)))
			//fmt.Println(len(v))
			if packetIterator < len(v) {
				packetCounter.Update(v[packetIterator])
				totalPackets += 1
			}
		}
		//Calculate the frequencies of elements
		elems, freqs := packetCounter.Freqs()
		// To create a map as input
		m := make(map[int]int)
		//Map dat shit
		for i := 0; i < len(elems); i++ {
			//interface casting stuffs
			elementValue, _ := elems[i].(uint8)
			m[int(elementValue)] = freqs[i]
		}
		//fmt.Println(m)
		//Sort map by value
		p := make(PairList, len(m))
		i := 0
		for k, v := range m {
			p[i] = Pair{k, v}
			i++
		}
		//Reverse sort so most common at the start
		//p is now sorted
		sort.Sort(sort.Reverse(p))
		//Count the number of packets at position
		//totalPackets := len(packets)
		//for i := 0; i < p.Len(); i++ {
		//	totalPackets += p[i].Value
		//}
		//print packet frequencies
		outstring += "\033[1;33m[ Byte " + strconv.Itoa(packetIterator) + " (0x" + fmt.Sprintf("%02x", packetIterator) + ")] Total: " + strconv.Itoa(totalPackets) + "\r\n"
		for i := 0; i < p.Len(); i++ {
			if i < maxComp {
				hexString := "\033[38;5;219m0x" + fmt.Sprintf("%02x", p[i].Key)
				fractionString := strconv.Itoa(p[i].Value) + "/" + strconv.Itoa(totalPackets)
				percentString := "(" + fmt.Sprintf("%.2f", 100*(float64(p[i].Value)/float64(totalPackets))) + "%)"
				outstring += "  " + hexString + " - " + fractionString + " " + percentString + "\r\n"
				//js.Global().Call("term.write", "  "+hexString+" - "+fractionString+" "+percentString)
			}
		}
	}
	return outstring
}

func pdiff(this js.Value, inputs []js.Value) interface{} {
	//javascript array of ints
	packetIds := inputs[0]
	callback := inputs[len(inputs)-1:][0]
	//make it a go slice of ints?
	var extractedPacketIds []int
	for i := 0; i < packetIds.Length(); i++ {
		extractedPacketIds = append(extractedPacketIds, packetIds.Index(i).Int())
	}
	//filter the cached packets to the requested list of id's
	filteredPackets := filterCachedPackets(extractedPacketIds)
	//A list to contain all of the packet lengths for averages
	var pLens []int
	for _, v := range filteredPackets {
		pLens = append(pLens, len(v))
	}

	callback.Invoke(listCommon(filteredPackets))
	return 1
}

func main() {
	fmt.Println("Go Web Assembly")
	c := make(chan bool)
	js.Global().Set("printPcap", js.FuncOf(printPcap))
	js.Global().Set("pdiff", js.FuncOf(pdiff))
	<-c
}
