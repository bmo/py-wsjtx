# ATNOtifier: help the stations who need you get in the log

ATNOtifier (`atnotifier.py`, formerly dupe_check) helps stations who need you for an **All-Time New One** get into
your log. It watches what WSJT-X decodes, looks each calling station up in your N1MM Logger+ log, and tells
WSJT-X how "worked" it is:

- **red** callsign: already worked in FT8 on this band (or FT4, with `include_ft4 = true`)
- **your own colors** for callsigns you list in `atnotifier_colors.txt` (see "Callsign colors" below)
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
- N1MM Logger+. ATNOtifier only *reads* its database, through a read-only connection, so N1MM can be running.
- WSJT-X. Red highlights work with stock WSJT-X. **The Score column needs a patched WSJT-X**: through at least
  3.2.0-rc1, WSJT-X receives the scores but never stores them, so the column always shows "-". The patch
  (`wsjtx-3.0.2-annotation-info.patch`, against v3.0.2) connects them.

## 1. Tell WSJT-X where to send its messages

In WSJT-X: **File > Settings > Reporting > UDP Server**.

WSJT-X sends each message to **one** address and port. If that address is an ordinary one like `127.0.0.1`,
only **one** program on the computer receives it, so ATNOtifier can't share it with another program. A
**multicast** address (224.x.x.x - 239.x.x.x) lets every program that joins it get a copy. So:

| WSJT-X setting | Value |
|---|---|
| UDP Server | `224.1.1.1` |
| UDP Server port number | `2238` (see "N1MM and port 2237" below) |
| Outgoing interfaces | include the loopback interface |

In our tests the red highlights worked with "Accept UDP requests" off; the scores were tested with it on, so
turn it on if scores don't appear.

## 2. Make a config file that matches

Copy `atnotifier.cfg.example` to `atnotifier.cfg` (in this folder) and set the `[wsjtx]` section to **exactly**
what WSJT-X uses:

```
[wsjtx]
address = 224.1.1.1
port = 2238
interface = 127.0.0.1
forward = 127.0.0.1:2237
```

`forward` passes WSJT-X's messages on to N1MM (see "N1MM and port 2237" below); these are the defaults, so a
config file isn't strictly needed for this setup.

Everything else can stay as it is to start with. By default ATNOtifier checks against the database N1MM has
open (read from `N1MM Logger.ini`), in all of its logs, and looks up only stations calling **you** (the
callsign WSJT-X reports).

## 3. Choose the log (optional)

```
python atnotifier.py --pick --save-config
```

lists the logs in N1MM's databases, with how many QSOs each has and when the last one was made; pick one and
it's saved in `atnotifier.cfg`. Or set `contest_nr` yourself: `all` (every log - "worked before, ever"),
`current` (the log N1MM has open), or a log number.

## 4. Start it

```
python atnotifier.py
```

You should see:

```
Checking callsigns against C:\Users\you\Documents\N1MM Logger+\Databases\ham.s3db, all logs (N1MM's current database)
Listening for WSJT-X on 224.1.1.1:2238 (interface 127.0.0.1); Ctrl-C to stop
Passing WSJT-X's messages on to 127.0.0.1:2237, and their replies back to WSJT-X
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
| `--forward HOST:PORT` | also pass WSJT-X's messages on to HOST:PORT (repeatable) |
| `--no-forward` | don't pass WSJT-X's messages on |
| `--colors FILE` | use another callsign colors file |
| `-v` | print every WSJT-X message (lots) |

## Callsign colors

To pick out particular stations - say, ones who've told you they need you for an ATNO - list them in
`atnotifier_colors.txt` beside `atnotifier.cfg` (copy `atnotifier_colors.txt.example`):

```
K1ABC      orange
W9XYZ      #ff00ff    white     ; asked for a sked on 40m
```

One callsign per line, a background color, and optionally a text color (otherwise black or white, whichever
reads better). Colors are HTML/CSS names written as one word (`orange`, `gold`, `lightblue`, `hotpink`, ...) or
codes like `#ff8800` or `#f80`. Lines starting with `#` or `;` are comments.

Whenever WSJT-X decodes a message from a listed station - calling you, calling someone else, or calling CQ -
ATNOtifier colors it, even if `match_my_call` limits the log lookups to stations calling you. A listed color
takes the place of the red "already worked" highlight; the station's score is still sent. The file is re-read
when it changes, so you can add stations while ATNOtifier runs.

Use another file with `--colors FILE`, or `callsign_colors` in `[atnotifier]`.

## N1MM and port 2237

N1MM Logger+'s own WSJT-X support listens on port **2237** (on all addresses), and while it does, no other
program can use that port - not even with multicast. WSJT-X also sends to only one place. So:

```
WSJT-X  -->  ATNOtifier (224.1.1.1:2238)  -->  N1MM (127.0.0.1:2237)
        <--  replies passed back           <--
```

WSJT-X sends to ATNOtifier on **2238**; ATNOtifier passes every message on to N1MM on **2237** (the `forward`
setting, on by default), and passes N1MM's replies - heartbeats, and the Reply sent when you double-click a call
in N1MM's WSJT-X window - back to WSJT-X. N1MM needs no changes, and keeps port 2237: ATNOtifier sends to it from
a port of its own and never opens 2237. For N1MM's double-click replies to work, turn on **Accept UDP requests**
in WSJT-X (Settings > Reporting).

`forward` takes several destinations (e.g. `127.0.0.1:2237 127.0.0.1:2239`) to feed other programs too. Only
one WSJT-X is supported: replies go to the WSJT-X ATNOtifier heard from most recently.

While ATNOtifier isn't running, N1MM's WSJT-X window gets nothing - start ATNOtifier along with WSJT-X.

ATNOtifier refuses to start on an ordinary (non-multicast) port another program already holds, rather than
quietly taking WSJT-X's messages away from it.

## Troubleshooting

**Coming from dupe_check?** ATNOtifier is the same program, renamed. If there's no `atnotifier.cfg` it uses your
`dupe_check.cfg` (and says so) - rename it when convenient; its `[dupe_check]` section is read as `[atnotifier]`.

**A listed callsign isn't colored** - check ATNOtifier's "Coloring N listed callsigns" message at startup and any
"line N: ..." complaints after it; the callsign must be spelled as WSJT-X decodes it (`K1ABC/P` and `K1ABC` are
different).

**"Nothing from WSJT-X for 30 seconds on 224.1.1.1:2238..."** - ATNOtifier is listening but nothing arrives.
WSJT-X's UDP Server address and port must match `[wsjtx]` in `atnotifier.cfg` exactly (a port mismatch is the
usual cause), and WSJT-X must be running.

**Messages arrive but nothing is looked up** - with `match_my_call = true` (the default), only stations
calling your callsign are looked up; check the callsign in WSJT-X. Set `match_my_call = false` to look up the
station sending every decoded message, CQs included.

**"Nothing is listening at 127.0.0.1:2237 (is N1MM running?)"** - N1MM (or whatever `forward` points at) isn't
listening yet. ATNOtifier keeps passing messages on, and says when it starts answering.

**"Not forwarding to 127.0.0.1:2238: ATNOtifier is listening on port 2238 itself..."** - `forward` points at
ATNOtifier's own port, which would send every message straight back. Forward to N1MM's port (2237) instead.

**"Port 2237 is in use by another program"** - usually N1MM. Use another port in both WSJT-X and
`atnotifier.cfg`, as above.

**Can't listen on 224.1.1.1:2237 (WinError 10013)** - the same thing with multicast: another program holds the
port exclusively. Use another port.

**Highlights but no scores** - the Score column needs the patched WSJT-X (see "What you need"), and is only in
Fox mode's "Stations calling" list.

**"No database set..."** - N1MM's ini file wasn't found or doesn't name a database. Set `database` in `[n1mm]`
(or `ini`, if N1MM's files aren't in `Documents\N1MM Logger+`), or use `--pick`.

## Tests

```
python test_atnotifier.py
```

checks the message parsing, scoring, lookup lines and WSJT-X message encoding; it needs neither WSJT-X nor N1MM.
