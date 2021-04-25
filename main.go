// +build js,wasm

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"syscall/js"

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
)

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
			callback.Invoke(js.Null(), packetCount, ipSrc, ipDst, tcpSrc, tcpDst, udpSrc, udpDst, payloadHex)
		}
	}
	callback.Invoke("Complete")
	return 1
}

func main() {
	fmt.Println("Go Web Assembly")
	c := make(chan bool)
	js.Global().Set("printPcap", js.FuncOf(printPcap))
	<-c
}
