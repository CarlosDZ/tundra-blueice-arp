# tundra-blueice-arp

ARP sensor of tundra-blueice, developed for Tundra OS, works on any Linux. It
probes an IPv4 address before it is used, then defends it and watches the
network while it is in use, reporting attacks as tundra-blueice alerts.

## Requirements

- Linux (uses `AF_PACKET`, `CLOCK_BOOTTIME`).
- Root (raw ARP sockets).

## Usage

```
tundra-blueice-arp probe <interface> <address> [accept <case>/<level>,...]
tundra-blueice-arp watch <interface> addr <address> [gw <address>]
                   [defend once|always] [accept <case>/<level>,...]
tundra-blueice-arp --version
```

### probe

Checks that the address is free before it is used and exits (RFC 5227: a random
wait of up to 1 s, three ARP probes 1-2 s apart, then 2 s of silence).

| stdout | Meaning |
|--------|---------|
| `free` | Nobody answered |
| `taken mac <sender> src <frame source>` | Another host uses the address; the probe stops at the first reply |

Every reply is recorded in the interface history and cases A, B and `mac-addr`
are evaluated over it. `accept` lists the cases approved by the user with their
maximum level: they are reported as warnings and the probe completes.

### watch

Watches an address in use until it is stopped. It announces the address twice,
2 s apart, learns the gateway MAC when `gw` is given (1 s of replies to an ARP
request) and then reads every ARP message on the interface, in this order:

| ARP sender | Checks |
|------------|--------|
| The address in use | Defense, C, `mac-addr` |
| The gateway | D, `mac-gw` |
| Anyone else with a crafted MAC | `mac-net` |

| Option | Meaning | Default |
|--------|---------|---------|
| `gw <address>` | Gateway to learn and watch | none |
| `defend once` | RFC 5227 policy (b): defend once, give the address up if it is claimed again within 10 s | yes |
| `defend always` | RFC 5227 policy (c): defend at most once every 10 s and never give up | |
| `accept <case>/<level>,...` | Approved cases, reported as warnings up to their level | none |

A warning is shown once per case and MAC. Losing carrier keeps the sensor
running; it watches again when the link comes back.

| Signal | Effect |
|--------|--------|
| SIGTERM, SIGINT | Exit with `0` |
| SIGHUP, SIGPIPE | Ignored |

### Exit status

| Code | `probe` | `watch` |
|------|---------|---------|
| `0` | Probe completed (`free` or `taken`) | Stopped by SIGTERM or SIGINT |
| `1` | Missing interface, interface down, socket error | Interface removed, socket error, or the address was given up: `conflict addr <address> mac <mac>` on stdout |
| `2` | Invalid usage | Invalid usage |
| `111` | Alert with action `stop` | Alert with action `stop` |

## Alerts

One line on stderr per alert:

```
alert 111/<level> <stop|warn> by tundra-blueice-arp on <if> ts <epoch.ms> reply <options> info case <case> [<key> <value>]... -- <text>
```

| Case | Action | Level | Mode | Condition |
|------|--------|-------|------|-----------|
| D | `stop` | 8 | watch | A second MAC answering for the gateway |
| `mac-gw` | `stop` | 8 | watch | A crafted MAC answering for the gateway, also while learning it |
| `mac-addr` | `stop` | 7 | both | A crafted MAC claiming the address |
| C | `stop` | 6 | watch | 3 claims on the address in use within 5 minutes |
| A | `stop` | 4 | probe | One MAC claiming 3 different addresses within 5 minutes |
| B | `stop` | 4 | probe | 10 distinct (MAC, address) pairs within 5 minutes |
| `mac-net` | `warn` | 2 | watch | A crafted MAC elsewhere on the network |

A crafted MAC is a multicast, broadcast or all-zero MAC, as ARP sender or as
Ethernet frame source. The forged hint (`forged 1`) marks an ARP sender that
differs from the frame source.

Values outside `[A-Za-z0-9._:@,/-]` are written as `%XX`.

## Files

| Path | Purpose |
|------|---------|
| `/run/tundra/blueice/arp/<if>` | Conflict history (5-minute window): one `at <ms> addr <ip> mac <mac> bound <0\|1> forged <0\|1>` line per record, times in milliseconds of `CLOCK_BOOTTIME` |
| `/run/tundra/blueice/arp/<if>.lock` | `flock` shared by concurrent writers |

## Building

```
make
make install PREFIX=/usr DESTDIR=<staging>
```

The Makefile honours the packager's `CPPFLAGS`, `CFLAGS` and `LDFLAGS`.

## Tests

```
make check-unit
make check
```

- `check-unit` runs the unit tests (`tests/unit/t-*.c`) built with
  AddressSanitizer and UBSan. No root needed.
- `check` runs the unit tests and then the network scenarios
  (`tests/net/t-*.sh`). They build an isolated testbed with network namespaces
  (a bridge, the sensor and an attacker) and never touch the host's
  interfaces. They need root (the runner re-executes itself with `sudo`) and
  `iproute2`.
- The test binary is built with protocol timers divided by 4.
