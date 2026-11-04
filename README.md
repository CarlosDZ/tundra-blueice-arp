# tundra-blueice-arp

ARP sensor of tundra-blueice, developed for Tundra OS, works on any Linux. It
probes an IPv4 address before it is used, then defends it and watches the
network while it is in use, reporting attacks as tundra-blueice alerts.

## Requirements

- Linux (uses `AF_PACKET`, `CLOCK_BOOTTIME`).
- Root (raw ARP sockets).

## Building

```
make
make install PREFIX=/usr DESTDIR=<staging>
```

The Makefile honours the packager's `CPPFLAGS`, `CFLAGS` and `LDFLAGS`.

## Tests

```
make check-unit
```

`check-unit` runs the unit tests (`tests/unit/t-*.c`) built with
AddressSanitizer and UBSan. No root needed.
