# domotic 5.02

Single-process C implementation of the original PHP home automation controller.

## Files

The complete project consists of only:

- `domotic.c` - controller, rule engine, hardware I/O and HTTP interface.
- `config` - log path and automation rules.
- `README.md` - this documentation.

Runtime files such as the configured log are created by the program and are not part of the source project.

## Build

The source follows the C89 programming style used by this project. Comments intentionally use `//`, therefore GCC should be invoked in GNU C89 mode:

```sh
gcc -std=gnu89 -O3 -Wall -Wextra -DPASSWORD='"your_password"' -o domotic domotic.c
```

Run it from the directory containing `config`:

```sh
./domotic
```

The process handles SIGINT and SIGTERM and closes open sockets and the log before exiting.

## Configuration

The first directives are:

```text
version 113
log domotic.log
```

The HTTP password is not stored in `config` and there is no default or fallback password in the source. It must be supplied at compile time with `-DPASSWORD`. Compilation without that definition intentionally fails.

Blank lines and lines beginning with `#` are ignored. Rules have this syntax:

```text
rule TYPE NUMERIC_VALUES... | NAME
```

Supported rule types are identical to the PHP controller:

- `0` 3level
- `1` onoff
- `2` on
- `3` off
- `4` alloff
- `6` injectifoff
- `7` injectifon
- `8` push
- `9` offtimed
- `10` offtimed_keysup
- `11` 3light

The `config` file contains the detailed argument layout and the complete rules translated from `config.php` version 113.

The parser validates rule type, field count, hours, minutes, key numbers and relay numbers. A malformed reload is rejected and the active configuration remains unchanged.

## Hardware

The controller preserves the original network layout:

- relay/input boards: `10.0.0.21` through `10.0.0.24`, TCP port `10001`;
- BEM input devices: `10.0.0.33` and `10.0.0.35`, TCP port `5000`;
- BEM relay devices: `10.0.0.32` and `10.0.0.34`, TCP port `5000`;
- HTTP server: `10.0.0.8:3333`.

There are 64 relays and 72 keys. Physical keys are 0-63 and virtual keys are 64-71. Physical key ranges are mapped exactly as in the PHP program: 0-11, 12-23, 24-35, 36-47, 48-55 and 56-63.

The four first boards are kept connected and automatically reconnected after communication errors. The BEM input connections are also reused. BEM output connections are opened only when their relay bank changes.

## Main loop

Each cycle:

1. reads all physical inputs;
2. detects key edges;
3. generates the release edge for keys injected during the preceding cycle;
4. runs minute-based rules when the minute changes;
5. serves pending HTTP commands;
6. runs key rules;
7. writes only changed relay banks;
8. records key timing data.

Timing uses `CLOCK_MONOTONIC`, so relay timers and press duration are not affected by wall-clock corrections.

## Rule behavior

`onoff` toggles its relay group on key release. If every relay is already on, all are turned off; otherwise all are turned on.

`on` and `off` force the configured group on or off on key release.

`alloff` switches off every relay except its configured skip list.

`push` follows key edge state: press switches the target group on and release switches it off.

`3level` reproduces the original PHP click state machine. If more than five seconds have elapsed since the previous release, the next click toggles both relay groups together. Further clicks released within five seconds cycle through the two levels.

`3light` uses the same five-second release-to-release window with three relay groups: the first click after an idle interval toggles the complete group, while subsequent clicks within the window cycle through the three levels.

`injectifoff` and `injectifon` inject a key at a configured hour/minute according to the state of another relay.

`offtimed` switches a relay off after the configured number of minutes.

`offtimed_keysup` does the same only while all configured keys are released.

Hour ranges that cross midnight are accepted (`start > end`), unlike the fragile direct comparison used by the original PHP code.

## HTTP interface

Requests use the same path layout as the original controller:

```text
http://10.0.0.8:3333/PASSWORD/COMMAND
```

Commands:

- `/PASSWORD/status`
- `/PASSWORD/keystatus`
- `/PASSWORD/inject/N`
- `/PASSWORD/set/N`
- `/PASSWORD/reset/N`
- `/PASSWORD/switchoff`
- `/PASSWORD/rule`
- `/PASSWORD/key`
- `/PASSWORD/relay`
- `/PASSWORD/log/N`
- `/PASSWORD/reload`
- `/PASSWORD/delete/N`
- `/PASSWORD/keyoff`
- `/PASSWORD/keyon`
- `/PASSWORD/help`

`delete` disables a rule only in memory. `reload` restores the rules from `config`.

The HTTP server is handled directly by the controller. The PHP implementation forked a process and generated `q3.php` to communicate commands back to the parent; neither mechanism is required here.

## Corrections and hardening

The C implementation intentionally fixes defects rather than reproducing them:

- the 4 high relays of each 12-relay Ethernet board use bits 4-7 of the B write register, exactly like the PHP controller;
- relay timing is initialized consistently; the PHP source wrote `$rete_time` while later code used `$rele_time`;
- configuration and HTTP numeric parameters are range checked before array access;
- malformed device responses do not overwrite the last known input state;
- network connections have finite timeouts and reconnect after failures;
- log retrieval reads the file directly and never executes a shell command;
- `reload` parses and validates a temporary configuration before replacing the active one;
- rule display handles all supported types; the PHP command code contains malformed labels such as `case4:` and `case10:`;
- virtual keys are correctly defined as 64-71;
- hour windows that cross midnight work correctly;
- wall-clock time and monotonic elapsed-time measurement are kept separate.

The hardware protocol and automation semantics reproduce the original public PHP source and `config.php` version 113. In particular, the five-second `3level`/`3light` interval is measured between releases, exactly as in the PHP state machine.
