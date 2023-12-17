# nomadcap

PCAP tool that aids in locating misconfigured network stacks.

The tool's function is to identify and capture Address Resolution Protocol (ARP)
requests that are not intended for the local network.

## Build

Install build essentials and PCAP library with headers.

```bash
sudo apt update
sudo apt install build-essential libpcap0.8 libpcap-dev
```

*Optional*. Compile with IEEE OUI CSV support. Install libcsv for parsing.

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

### Output

Capturing on interface `wlo1` for network `192.168.2.0` with subnet mask `255.255.255.0`.
In this example `10.0.70.5` is the misconfigured host looking for the default gateway `10.0.70.1`.

```text
Looking for interface...
Found interface: wlo1
Flags: 0x00000001
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
ARP announcement, ignoring...
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
^CInterrupt signal caught...
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1

Packets received: 5
Packets dropped: 0
```
