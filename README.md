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
tundra-blueice-arp --version
```

### probe

Checks that the address is free before it is used and exits (RFC 5227: a random
wait of up to 1 s, three ARP probes 1-2 s apart, then 2 s of silence).

| stdout | Exit | Meaning |
|--------|------|---------|
| `free` | `0` | Nobody answered |
| `taken mac <sender> src <frame source>` | `0` | Another host uses the address |
| — | `111` | Alert with action `stop`, written on stderr |
| — | `1` | Operational failure: missing interface, socket error |
| — | `2` | Invalid usage |

Every reply is recorded in the interface history and cases A, B and `mac-addr`
are evaluated over it. `accept` lists the cases approved by the user with their
maximum level: they are reported as warnings and the probe completes.

## Alerts

One line on stderr per alert:

```
alert 111/<level> <stop|warn> by tundra-blueice-arp on <if> ts <epoch.ms> reply <options> info case <case> [<key> <value>]... -- <text>
```

| Case | Action | Level | Condition |
|------|--------|-------|-----------|
| A | `stop` | 4 | One MAC claiming 3 different addresses within 5 minutes |
| B | `stop` | 4 | 10 distinct (MAC, address) pairs within 5 minutes |
| `mac-addr` | `stop` | 7 | A multicast, broadcast or all-zero MAC, as ARP sender or frame source, claiming the address |

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
