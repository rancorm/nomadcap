# nomadcap

[PCAP](https://en.wikipedia.org/wiki/Pcap) tool that aids in locating misconfigured network stacks.

The tool's function is to identify [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) (ARP)
requests that are not intended for the local network.

## Features

- Live capture on specific interface (-i en0)
- Offline capture from file (-f /path/to/capture.file)
- Network (-n) and [netmask](https://en.wikipedia.org/wiki/Subnet) (-m) override
- Monitor specific [VLANs](https://en.wikipedia.org/wiki/VLAN) (--vlan X,Y)
- Capture for a duration (-d 60)
- Execute script/program on detection (-x /path/to/script.sh)
- Exit on single match (-1)
- [MAC](https://en.wikipedia.org/wiki/MAC_address)/OUI to organization look up using IEEE [OUI](https://en.wikipedia.org/wiki/Organizationally_unique_identifier) data (-O) - *libcsv & ieee-data* 
- Process all networks (-A) as a basic request monitor
- Process [probes](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#ARP_probe) (-p) and [announcements](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#ARP_announcements) (-a)
- Quick list of interfaces with details (-L)
- [JSON](https://en.wikipedia.org/wiki/JSON) output (-j) - *libjansson*
- Syslog support (-s)
- [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) timestamps both local (-t) and UTC (-u)
- Verbose mode (-v)

## Dependencies

- libc6
- libpcap0.8
- libcsv3 & ieee-data - *optional*
- libjansson4 - *optional*

### Build Dependencies

If you are compiling from source you will need the following packages.

- build-essential
- libpcap-dev
- libcsv-dev - *optional*
- libjansson-dev - *optional*

## Get Started

### Debian

Download the [latest release](https://github.com/jcormir/nomadcap/releases/latest) Debian package (.deb) and
install using `dpkg` or your favourite [APT](https://en.wikipedia.org/wiki/APT_(software)) front-end.

```zsh
VER="0.5-1"
sudo dpkg -i nomadcap_${VER}_amd64.deb
```

### Build

Install required build tools, libraries, and headers.

```zsh
sudo apt update
sudo apt install build-essential libpcap0.8 libpcap-dev
```

*Optional*. Compile with IEEE OUI support. Install libcsv for parsing.

```zsh
sudo apt install libcsv3 libcsv-dev ieee-data
```

*Optional*. Compile with JSON support. Install libjansson for JSON output.

```zsh
sudo apt install libjansson4 libjansson-dev
```

Clone this repository and run `make`. Results are in the directory `build/`.

```zsh
git clone https://github.com/rancorm/nomadcap.git
cd nomadcap
make
build/nomadcap -h
```

## Usage

General tool and command line switch usage.

### Help

Run `nomadcap -h` to show help.

```zsh
nomadcap -h
```

#### Menu

```text
nomadcap v0.5 [Misconfigure network stack identification tool]

Usage: nomadcap [-i INTF] [-n NETWORK -m NETMASK] [--vlan X,Y,Z] [-f FILE.PCAP] [-d SECONDS] [-x PATH] [-OjApa1stuLvV]

Options:
  -i, --interface=INTF      Capture on specific interface
  -n, --network=NETWORK     Capture network (e.g. 192.0.2.0)
  -m, --mask=NETMASK        Capture netmask (e.g. 255.255.255.0)
  --vlan X,Y,Z              Specific VLANs to monitor
  -f, --file=FILE.PCAP      Offline capture using FILE.PCAP
  -d, --duration=SECONDS    Duration of capture (default: 60, forever: 0)
  -O, --oui                 MAC OUI to organization
  -A, --all                 All networks (ARP request monitor)
  -p, --probes              Process ARP probes
  -a, --announce            Process ARP announcements
  -1, --once                Exit after single match
  -x, --exec=PATH           Execute on detection
  -s, --syslog              Send to syslog
  -t, --timestamp           ISO 8601 timestamps
  -u, --utc                 Show timestamps in UTC
  -L, --list                List available interfaces
  -j, --json                JSON output
  -v, --verbose             Verbose mode
  -V, --version             Version
  -h, --help                Help screen

Author: Jonathan Cormier <jonathan@cormier.co>
```

### Examples

Run `nomadcap` under sudo, root, or group with permission to perform live capture.

#### Example 1

```zsh
sudo nomadcap -v
```

Capture on found interface `wlo1` for network `192.168.2.0` with subnet mask `255.255.255.0`.
In this example `10.0.70.5` is the misconfigure host looking for the default gateway `10.0.70.1`.

Capture for the default duration of 60 seconds.

```text
Looking for interface...
Found interface: wlo1
Flags: 0x00000001
Duration: 60 seconds
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
Syslog: 0
Started at: 1982-06-26T08:50:09.885-0400
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
ARP announcement, ignoring...
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1
^CInterrupt signal
10.0.70.5 [dc:a6:32:e7:ec:72] is looking for 10.0.70.1

Packets received: 5
Packets dropped: 0
Done
```

#### Example 2

```zsh
sudo nomadcap -Ov -1 -d 0
```

Another example using single match (-1), OUI look up (-O), verbose mode (-v), and
capture forever (-d 0) features.

```text
Looking for interface...
Found interface: wlo1
Flags: 0x00000241
Loading OUI data from /usr/share/ieee-data/oui.csv...
Loaded 32,531 OUIs
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
Syslog: 0
Started at: 2024-01-11T04:20:09.885-0400
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
Local traffic, ignoring...
10.0.70.252 [a4:2a:95:15:c9:10 - D-Link International] is looking for 10.0.70.1

Packets received: 10
Packets dropped: 0
Done
```

#### Example 3

```zsh
nomadcap -Ov -f nomad.pcapng
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
Loaded 32,531 OUIs
Loading capture file: nomad.pcapng
Listening on: wlo1
Local network: 192.168.2.0
Network mask: 255.255.255.0
Syslog: 0
Started at: 2024-01-06T02:50:09.885-0400
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
Done
```
#### Example 4

```zsh
sudo nomadcap -Ov -j -1 -t
```

Capture single match (-1) with organization details (-O), verbose mode (-v), JSON mode (-j), and
with timestamps (-t). JSON mode prints a JSON object with capture details and results.

```text
{
  "found_intf": "wlo1",
  "flags": 1601,
  "oui_file": "/usr/share/ieee-data/oui.csv",
  "ouis": 32531,
  "duration": 60,
  "listening_on": "wlo1",
  "localnet": "192.168.2.0",
  "netmask": "255.255.255.0",
  "results": [
    {
      "src_ip": "10.0.70.252",
      "src_ha": "a4:2a:95:15:c9:10",
      "tgt_ip": "10.0.70.1",
      "ts": "2024-01-06T02:50:09.885-0400",
      "org": "D-Link International"
    }
  ],
  "started_at": "2024-01-06T01:50:03.245-0400",
  "stats": {
    "pkts_recv": 4,
    "pkts_drop": 0
  },
  "version": "0.5"
}%
```

#### Example 5

```zsh
sudo nomadcap -i en0 -d 0 -v -x scripts/echo.sh
```

Capture forever (-d 0) in verbose mode (-v) on interface `en0` (-i). When there is a
detection, run the script or program passed to the argument `-x`, in our example
`echo.sh` which just prints to stdout.

```zsh
Flags: 0x00000001
Binary: scripts/echo.sh
Listening on: en0
Local network: 192.168.2.0
Network mask: 255.255.255.0
Syslog: 0
Started at: 2025-05-13T05:54:00.091-0300
Local traffic, ignoring...
Local traffic, ignoring...
10.0.80.2 [30:23:03:8d:f5:e3] is looking for 10.0.80.1
Executing 'scripts/test.sh'...
Detected host! src: 10.0.80.2 [30:23:03:8d:f5:e3], tgt: 10.0.80.1 [00:00:00:00:00:00]
```

## nomadcap6

`nomadcap6` is the IPv6 companion to `nomadcap`. Instead of monitoring ARP, it captures
[ICMPv6](https://en.wikipedia.org/wiki/ICMPv6) [Neighbor Discovery Protocol](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol)
(NDP) traffic — specifically Neighbor Solicitation (NS) and Neighbor Advertisement (NA) messages —
to identify hosts soliciting addresses outside the local network prefix.

### Key Differences from nomadcap

- Network is specified as a single CIDR prefix (`-n fe80::/10`) instead of separate `-n` and `-m` flags
- Monitors NDP (ICMPv6) rather than ARP
- No `-p` (probes) or `-m` (netmask) options

### Help

Run `nomadcap6 -h` to show help.

```zsh
nomadcap6 -h
```

#### Menu

```text
nomadcap6 v0.5 [Misconfigure v6 network stack identification tool]

Usage: nomadcap6 [-i INTF] [-n PREFIX/LENGTH] [--vlan X,Y,Z] [-f FILE.PCAP] [-d SECONDS] [-x PATH] [-OjAa1stuLvV]

Options:
  -i, --interface=INTF      Capture on specific interface
  -n, --network=PREFIX/LEN  Capture network (e.g. fe80::/10)
  --vlan X,Y,Z              Specific VLANs to monitor
  -f, --file=FILE.PCAP      Offline capture using FILE.PCAP
  -d, --duration=SECONDS    Duration of capture (default: 60, forever: 0)
  -O, --oui                 MAC OUI to organization
  -A, --all                 All networks
  -a, --announce            Process unsolicited neighbor advertisements
  -1, --once                Exit after single match
  -x, --exec=PATH           Execute on detection
  -s, --syslog              Send to syslog
  -t, --timestamp           ISO 8601 timestamps
  -u, --utc                 Show timestamps in UTC
  -L, --list                List available interfaces
  -j, --json                JSON output
  -v, --verbose             Verbose mode
  -V, --version             Version
  -h, --help                Help screen

Author: Jonathan Cormier <jonathan@cormier.co>
```

### Example

```zsh
sudo nomadcap6 -Ov -1 -d 0
```

Single match (-1), OUI look up (-O), verbose mode (-v), capture forever (-d 0).

```text
Looking for interface...
Found interface: wlo1
Flags: 0x00000241
Loading OUI data from /usr/share/ieee-data/oui.csv...
Loaded 32,531 OUIs
Listening on: wlo1
Network prefix: fe80::/64
Started at: 2025-05-13T05:54:00.091-0300
Local traffic, ignoring...
2001:db8:1::5 [dc:a6:32:e7:ec:72 - Raspberry Pi Trading Ltd] is looking for 2001:db8:1::1

Packets received: 8
Packets dropped: 0
Done
```
