# pdiffwasm

In Action: https://remyhax.xyz/tools/pdiffwasm/

WebAssembly Implementation written in Go of a Wireshark style interface for parsing and displaying PCAP files in browser.

Includes built in frequency analysis for basic protocol RE implmeneted similarly to https://github.com/netspooky/pdiff

Watch https://www.youtube.com/watch?v=FKbVNXnR10A for a better understanding of it's uses.

GOOS=js GOARCH=wasm go build -o main.wasm main.go
