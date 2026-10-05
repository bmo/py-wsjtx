# dupe_check: show worked stations in WSJT-X

`dupe_check.py` watches what WSJT-X decodes, looks each calling station up in your N1MM Logger+ log, and tells
WSJT-X how "worked" it is:

- **red** callsign: already worked in FT8 on this band (or FT4, with `include_ft4 = true`)
- a **score** for each worked station, shown in the Score column of WSJT-X's Fox-mode "Stations calling" list and
  used by its *Score* sort (lowest first, so unworked stations come first)

| Earlier QSOs with the station | Score each |
|---|---|
| FT8 on the current band | 2000 |
| another mode on the current band | 300 |
| any other band | 20 |

Scores are added up and capped at 50000 (WSJT-X's limit). Stations not in the log get no score.

## What you need

- Python 3.6 or later, run from this `samples` folder (it uses the `pywsjtx` package one level up).
- N1MM Logger+. dupe_check only *reads* its database, through a read-only connection, so N1MM can be running.
- WSJT-X. Red highlights work with stock WSJT-X. **The Score column needs a patched WSJT-X**: through at least
  3.2.0-rc1, WSJT-X receives the scores but never stores them, so the column always shows "-". The patch
  (`wsjtx-3.0.2-annotation-info.patch`, against v3.0.2) connects them.

## 1. Tell WSJT-X where to send its messages

In WSJT-X: **File > Settings > Reporting > UDP Server**.

WSJT-X sends each message to **one** address and port. If that address is an ordinary one like `127.0.0.1`,
only **one** program on the computer receives it, so dupe_check can't share it with another program. A
**multicast** address (224.x.x.x - 239.x.x.x) lets every program that joins it get a copy. So:

| WSJT-X setting | Value |
|---|---|
| UDP Server | `224.1.1.1` |
| UDP Server port number | `2238` (see "N1MM and port 2237" below) |
| Outgoing interfaces | include the loopback interface |

In our tests the red highlights worked with "Accept UDP requests" off; the scores were tested with it on, so
turn it on if scores don't appear.

## 2. Make a config file that matches

Copy `dupe_check.cfg.example` to `dupe_check.cfg` (in this folder) and set the `[wsjtx]` section to **exactly**
what WSJT-X uses:

```
[wsjtx]
address = 224.1.1.1
port = 2238
interface = 127.0.0.1
```

Everything else can stay as it is to start with. By default dupe_check checks against the database N1MM has
open (read from `N1MM Logger.ini`), in all of its logs, and looks up only stations calling **you** (the
callsign WSJT-X reports).

## 3. Choose the log (optional)

```
python dupe_check.py --pick --save-config
```

lists the logs in N1MM's databases, with how many QSOs each has and when the last one was made; pick one and
it's saved in `dupe_check.cfg`. Or set `contest_nr` yourself: `all` (every log - "worked before, ever"),
`current` (the log N1MM has open), or a log number.

## 4. Start it

```
python dupe_check.py
```

You should see:

```
Checking callsigns against C:\Users\you\Documents\N1MM Logger+\Databases\ham.s3db, all logs (N1MM's current database)
Listening for WSJT-X on 224.1.1.1:2238 (interface 127.0.0.1); Ctrl-C to stop
22:16:33Z  YT0A         14 MHz  score    600  JTTY 14 MHz x2
22:16:33Z  K1XYZ        14 MHz  not in log
```

one line per station looked up. If no lines appear, see "Troubleshooting".

Options:

| Option | Does |
|---|---|
| `-c FILE` | use another config file |
| `--pick` | choose the log from a list (`--save-config` remembers it) |
| `--no-show-lookups` | print only stations already worked (`-l` turns every lookup back on) |
| `-v` | print every WSJT-X message (lots) |

## N1MM and port 2237

N1MM Logger+'s own WSJT-X support listens on port **2237** (on all addresses), and while it does, no other
program can use that port - not even with multicast. That's why the setup above uses **2238** for WSJT-X and
dupe_check.

The catch: WSJT-X sends to only one place, so while it sends to 224.1.1.1:2238, N1MM's WSJT-X window hears
nothing. If you need both, `wsjtx_packet_exchanger.py` in this folder was written to pass WSJT-X's messages on
to other programs, but it needs editing for these addresses and ports (see the comments at its top) and hasn't
been tried with this setup.

dupe_check refuses to start on an ordinary (non-multicast) port another program already holds, rather than
quietly taking WSJT-X's messages away from it.

## Troubleshooting

**"Nothing from WSJT-X for 30 seconds on 224.1.1.1:2238..."** - dupe_check is listening but nothing arrives.
WSJT-X's UDP Server address and port must match `[wsjtx]` in `dupe_check.cfg` exactly (a port mismatch is the
usual cause), and WSJT-X must be running.

**Messages arrive but nothing is looked up** - with `match_my_call = true` (the default), only stations
calling your callsign are looked up; check the callsign in WSJT-X. Set `match_my_call = false` to look up the
station sending every decoded message, CQs included.

**"Port 2237 is in use by another program"** - usually N1MM. Use another port in both WSJT-X and
`dupe_check.cfg`, as above.

**Can't listen on 224.1.1.1:2237 (WinError 10013)** - the same thing with multicast: another program holds the
port exclusively. Use another port.

**Highlights but no scores** - the Score column needs the patched WSJT-X (see "What you need"), and is only in
Fox mode's "Stations calling" list.

**"No database set..."** - N1MM's ini file wasn't found or doesn't name a database. Set `database` in `[n1mm]`
(or `ini`, if N1MM's files aren't in `Documents\N1MM Logger+`), or use `--pick`.

## Tests

```
python test_dupe_check.py
```

checks the message parsing, scoring, lookup lines and WSJT-X message encoding; it needs neither WSJT-X nor N1MM.
