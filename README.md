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
- JSON output (-j) - *libjansson*
- Verbose mode (-v)

## Get Started

Install build essentials and PCAP library with headers.

```bash
sudo apt update
sudo apt install build-essential libpcap0.8 libpcap-dev
```

*Optional*. Compile with IEEE OUI support. Install libcsv for parsing.

```bash
sudo apt install libcsv3 libcsv-dev ieee-data
```

*Optional*. Compile with JSON support. Install libjansson for JSON output.

```bash
sudo apt install libjansson4 libjansson-dev
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

Usage: nomadcap [-i INTF] [-n NETWORK -m NETMASK] [-f FILE.PCAP] [-d SECONDS] [-OjApa1LvV]

        -i INTF         Capture on specific interface
        -n NETWORK      Capture network (e.g. 192.0.2.0)
        -m NETMASK      Capture netmask (e.g. 255.255.255.0)
        -f FILE.PCAP    Offline capture using FILE.PCAP
        -d SECONDS      Duration of capture (default: 60, forever: 0)
        -O              MAC OUI to organization
        -A              All networks (ARP request monitor)
        -p              Process ARP probes
        -a              Process ARP announcements
        -1              Exit after single match
        -L              List available interfaces
        -j              JSON output
        -v              Verbose mode
        -V              Version
```

### Capture

Run `nomadcap` under sudo, root, or group with permission to perform live capture.

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
^CInterrupt signal
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1

Packets received: 5
Packets dropped: 0
```

#### Example 2

```bash
sudo build/nomadcap -Ov -1
```

Another example using single match (-1), OUI look up (-O) and Verbose mode (-v) features.

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

#### Example 3

```bash
build/nomadcap -Ov -f nomad.pcapng
```

Read from offline file (-f) `nomad.pcapng` in verbose mode (-v) with OUI look up (-O).

Note, the warning about using -f without -n, in this example capture came from same network
as interface, otherwise we would have used -n and -m switch respectfully.

Also note, it's run with standard user privileges.

```text
WARNING: Using -f (file) capture without -n (network) switch
Looking for interface...
Found interface: wlo1
Flags: 0x00000221
Loading OUI data from /usr/share/ieee-data/oui.csv...
Loaded 32531 OUIs
Loading capture file: nomad.pcapng
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
Local traffic, ignoring...
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 10.0.70.1
Reached end of capture file: nomad.pcapng
```
#### Example 4

```sh
sudo build/nomadcap -Ov -j -1
```

Capture single match (-1) with organization details (-O) in verbose (-v) and JSON mode (-j).
JSON mode prints a JSON object with capture details and results (if any).

```text
{
  "found_intf": "wlo1",
  "flags": 1601,
  "oui_file": "/usr/share/ieee-data/oui.csv",
  "ouis": 32531,
  "listening_on": "wlo1",
  "localnet": "192.168.2.0",
  "netmask": "255.255.255.0",
  "results": [
    {
      "src_ip": "10.0.70.252",
      "src_ha": "a4:2a:95:15:c9:10",
      "tgt_ip": "10.0.70.1",
      "org": "D-Link International"
    }
  ],
  "stats": {
    "pkts_recv": 4,
    "pkts_drop": 0
  },
  "version": "0.1"
}%
```
