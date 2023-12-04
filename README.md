# nomadcap

PCAP tool that aids in locating misconfigured network stacks

## Build

Install build essentials and PCAP library with headers.

```bash
sudo apt update
sudo apt install build-essential libpcap0.8 libpcap-dev
```

(Optional) Compile with IEEE OUI CSV support. Install libcsv for parsing.

```bash
sudo apt install libcsv3 libcsv3-dev
```

Clone this repository and run `make`. Results are in the directory `build/`.

```bash
git clone https://github.com/jcormir/nomadcap.git
cd nomadcap
make
```

## Usage

Run `nomadcap` with root privileges or through `sudo`.

```bash
sudo build/nomadcap -v
```

Output:

```
Flags: 0x00000003
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
Filter: arp
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
^CInterrupt signal caught...
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1

Packets received: 5
Packets dropped: 0
```
