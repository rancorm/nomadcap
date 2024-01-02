# nomadcap

PCAP tool that aids in locating misconfigured network stacks.

The tool's function is to identify and capture Address Resolution Protocol (ARP)
requests that are not intended for the local network.

## Features

- Live capture on specific interface (-i)
- Offline capture from file (-f)
- Network (-n) and netmask (-m) override
- Run capture for a duration (-d)
- Exit on single match (-1)
- MAC/OUI to organization look up using IEEE OUI data (-O) - *libcsv*
- Process all networks (-A) as a basic request monitor
- Process probes (-p) and announcements (-a)
- Quick list of intefaces with details (-L)
- Verbose mode (-v)

## Get Started

Install build essentials and PCAP library with headers.

```bash
sudo apt update
sudo apt install build-essential libpcap0.8 libpcap-dev
```

*Optional*. Compile with IEEE OUI CSV support. Install libcsv for parsing.

```bash
sudo apt install libcsv3 libcsv-dev ieee-data
```

Clone this repository and run `make`. Results are in the directory `build/`.

```bash
git clone https://github.com/jcormir/nomadcap.git
cd nomadcap
make
```

## Usage

General tool and command line switch usage.

### Help

Run `nomadcap -h` to show help.

```bash
build/nomadcap -h
```

#### Menu

```text
nomadcap v0.1 [Mis-configured network stack identification tool]

Usage: nomadcap [-i intf] [-n network -m netmask] [-f filename.pcap] [-d seconds] [-OApa1LvV]

        -i intf                 Capture on specific interface
        -n network              Capture network (e.g. 192.0.2.0)
        -m netmask              Capture netmask (e.g. 255.255.255.0)
        -f filename.pcap        Offline capture using filename.pcap
        -d seconds              Duration of capture (seconds)
        -O                      MAC OUI to organization
        -A                      All networks (ARP request monitor)
        -p                      Process ARP probes
        -a                      Process ARP announcements
        -1                      Exit after single match
        -L                      List available interfaces
        -v                      Verbose mode
        -V                      Version
```

### Capture

Run `nomadcap` with root privileges or through `sudo` to allow capturing of traffic.

#### Example 1

```bash
sudo build/nomadcap -v
```

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

#### Example 2

```bash
sudo build/nomadcap -Ov -1
```

Another example using Single Match (1), OUI Lookup (O) and Verbose Mode (v) features.

```text
Looking for interface...
Found interface: wlo1
Flags: 0x00000241
Loading OUI data from /usr/share/ieee-data/oui.csv...
Loaded 32531 OUIs
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
10.0.70.252 [a4:2a:95:15:c9:10 - D-Link International] is looking for 10.0.70.1

Packets received: 10
Packets dropped: 0
```
