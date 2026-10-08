#
# Finding N1MM Logger+'s databases and the logs in them, for samples that read N1MM's log (e.g. atnotifier.py).
#
# N1MM records its current database and log in "N1MM Logger.ini" ([Configurer] DXLog Name / Contest NR), so a
# program can follow it without being told; and each database's ContestInstance table lists its logs.
#
import glob, os, pathlib, re, shutil, sqlite3, sys

# databases N1MM keeps for itself, not logs
NOT_LOGS = ('n1mm admin.s3db', 'n1mm packet spots.s3db')
# N1MM keeps deleted QSOs in this pseudo-log
DELETED_CONTEST_NR = -1


def default_n1mm_folder():
    return os.path.join(os.path.expanduser('~'), 'Documents', 'N1MM Logger+')


def default_ini_path():
    return os.path.join(default_n1mm_folder(), 'N1MM Logger.ini')


def default_database_folder():
    return os.path.join(default_n1mm_folder(), 'Databases')


def read_n1mm_ini(path):
    """ What N1MM's ini file says about the current log. Returns a dict with any of: 'database' (file name),
        'contest_nr', 'contest_name', and 'recent' [(contest name, start date, database path, contest nr)], or {}. """
    try:
        with open(path, encoding='utf-8-sig', errors='replace') as f:
            lines = f.read().splitlines()
    except OSError:
        return {}

    info, recent, section = {}, [], None
    for line in lines:
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            continue
        if section != 'Configurer' or '=' not in line:
            continue
        key, value = (part.strip() for part in line.split('=', 1))
        if key == 'DXLog Name':
            info['database'] = value
        elif key == 'Contest NR':
            try:
                info['contest_nr'] = int(value)
            except ValueError:
                pass
        elif key == 'Contest Type':
            info['contest_name'] = value
        elif key.startswith('RecentContest'):
            parts = value.split('|')  # DXPEDITION|2026-08-15 00:00:00|C:\...\ham.s3db|2
            if len(parts) >= 4:
                try:
                    recent.append((parts[0], parts[1], parts[2], int(parts[3])))
                except ValueError:
                    pass
    if recent:
        info['recent'] = recent
    return info


def current_log(ini_path=None, database_folder=None):
    """ (database path, contest nr, contest name) of the log N1MM has open, from its ini file, or None. """
    info = read_n1mm_ini(ini_path or default_ini_path())
    name = info.get('database')
    if not name:
        return None
    path = name
    if not os.path.isabs(path):
        # the ini has just the file name; the recent-logs list usually has the full path
        recent = [p for _, _, p, _ in info.get('recent', []) if os.path.basename(p).lower() == name.lower()]
        path = recent[0] if recent else os.path.join(database_folder or default_database_folder(), name)
    return os.path.normpath(path), info.get('contest_nr'), info.get('contest_name')


def find_databases(folders):
    """ N1MM log databases (*.s3db) in the given folders, skipping N1MM's own admin and spots databases. """
    found = []
    for folder in folders:
        for path in sorted(glob.glob(os.path.join(folder, '*.s3db'))):
            if os.path.basename(path).lower() not in NOT_LOGS and os.path.normcase(path) not in map(os.path.normcase, found):
                found.append(path)
    return found


def open_readonly(database_path):
    """ A read-only connection to an N1MM database: safe while N1MM has it open, and can never change the log. """
    if not os.path.exists(database_path):  # connect() would quietly create an empty file
        raise FileNotFoundError(database_path)
    return sqlite3.connect(pathlib.Path(os.path.abspath(database_path)).as_uri() + '?mode=ro', uri=True)


def list_logs(database_path):
    """ [(contest nr, contest name, start date, description, QSO count, last QSO time), ...] for the logs in an
        N1MM database (not its deleted-QSO area). The description is the contest's display name from N1MM's Contest
        table, as N1MM's own log picker shows it; the last QSO time is N1MM's TS (UTC), or None for an empty log. """
    cx = open_readonly(database_path)
    try:
        logs = cx.execute('SELECT ContestNR, ContestName, StartDate FROM ContestInstance WHERE ContestNR <> ? ORDER BY ContestNR',
                          (DELETED_CONTEST_NR,)).fetchall()
        stats = {nr: (count, last) for nr, count, last in
                 cx.execute('SELECT ContestNR, count(*), max(TS) FROM DXLOG GROUP BY ContestNR').fetchall()}
        try:
            descriptions = dict(cx.execute('SELECT Name, DisplayName FROM Contest').fetchall())
        except sqlite3.Error:
            descriptions = {}
    finally:
        cx.close()
    return [(nr, name, start, descriptions.get(name) or '', stats.get(nr, (0, None))[0], stats.get(nr, (0, None))[1])
            for nr, name, start in logs]


def choose_log(databases, current=None, ask=None, say=None):
    """ List every log in the databases and let the operator pick one.
        current: (database path, contest nr) of N1MM's current log, offered as the default.
        Returns (database path, contest nr, contest name), or None if they choose not to pick. """
    ask = ask or input
    say = say or print
    choices = []
    for path in databases:
        try:
            logs = list_logs(path)
        except Exception as e:
            say("  (can't read {path}: {e})".format(path=path, e=e))
            continue
        for nr, name, start, description, qsos, last_qso in logs:
            choices.append((path, nr, name, start, description, qsos, last_qso))
    if not choices:
        say("No N1MM logs found to choose from.")
        return None

    default = None
    # the log with the newest QSO is probably the one used last
    latest = max((c[6] for c in choices if c[6]), default=None)
    row = "  {n:>3}  {db:<16} {nr:>4}  {name:<12} {start:<16} {description:<18} {qsos:>5}  {last:<17}{mark}"
    say("")
    say("Logs in N1MM's databases:")
    say(row.format(n='', db='Database', nr='Log', name='Contest', start='Start date', description='Description', qsos='QSOs',
                   last='Last QSO (UTC)', mark=''))
    # numbered from 0, like N1MM's logs, so a single database's choice numbers line up with its log numbers
    for n, (path, nr, name, start, description, qsos, last_qso) in enumerate(choices):
        is_current = current is not None and os.path.normcase(path) == os.path.normcase(current[0]) and nr == current[1]
        if is_current:
            default = n
        # start dates look like "2026-08-15 00:00:00"; midnight is N1MM's "no time given"
        start = (start or '').strip()
        start = start[:16] if start[11:16] not in ('', '00:00') else start[:10]
        marks = (["N1MM's current log"] if is_current else []) + (["latest QSO"] if latest and last_qso == latest else [])
        say(row.format(n='%d)' % n, db=os.path.basename(path)[:16], nr='#%d' % nr, name=(name or '?')[:12], start=start,
                       description=description[:18], qsos=qsos, last=(str(last_qso)[:16] + 'Z') if last_qso else '-',
                       mark=('  <- ' + ', '.join(marks)) if marks else ''))
    prompt = "Pick a log (0-{last}{default}, or q to skip): ".format(
        last=len(choices) - 1, default=", Enter = {d}".format(d=default) if default is not None else '')
    while True:
        try:
            answer = ask(prompt).strip().lower()
        except EOFError:
            return None
        if answer in ('q', 'quit', 's', 'skip'):
            return None
        if answer == '' and default is not None:
            answer = str(default)
        if answer.isdigit() and int(answer) < len(choices):
            path, nr, name = choices[int(answer)][:3]
            return path, nr, name
        say("  Enter a number from 0 to {last}, or q.".format(last=len(choices) - 1))


def keyboard_attached():
    """ True when someone could answer a prompt. On Windows isatty() is also true for NUL, so ask the console. """
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
        if os.name == 'nt':
            import ctypes, msvcrt
            mode = ctypes.c_uint32()
            return bool(ctypes.windll.kernel32.GetConsoleMode(msvcrt.get_osfhandle(sys.stdin.fileno()), ctypes.byref(mode)))
        return True
    except (OSError, ValueError, AttributeError):
        return False


def update_config_file(path, section, values):
    """ Set keys in one section of a config file, editing just those lines so comments and layout survive
        (configparser's own writer drops comments). A commented-out example of a key is replaced in place.
        Creates the file if it doesn't exist; keeps the previous version as path.bak. """
    text = ''
    if os.path.exists(path):
        with open(path, newline='') as f:
            text = f.read()
        shutil.copyfile(path, path + '.bak')
    nl = '\r\n' if '\r\n' in text else os.linesep
    lines = text.splitlines()

    header = re.compile(r'^\s*\[(.*)\]\s*$')
    start = next((i for i, line in enumerate(lines) if header.match(line) and header.match(line).group(1).strip() == section), None)
    if start is None:
        lines += (['', ] if lines else []) + ['[{0}]'.format(section)]
        start = len(lines) - 1
    end = next((i for i in range(start + 1, len(lines)) if header.match(lines[i])), len(lines))

    for key, value in values.items():
        active = re.compile(r'^(\s*{0}\s*[=:]\s*)(.*)$'.format(re.escape(key)), re.IGNORECASE)
        example = re.compile(r'^\s*[#;]\s*{0}\s*[=:]'.format(re.escape(key)), re.IGNORECASE)
        for i in range(start + 1, end):
            m = active.match(lines[i])
            if m:
                comment = re.search(r'\s+#.*$', m.group(2))  # keep an inline comment
                lines[i] = m.group(1) + str(value) + (comment.group(0) if comment else '')
                break
        else:
            at = next((i for i in range(start + 1, end) if example.match(lines[i])), None)
            if at is not None:
                lines[at] = '{0} = {1}'.format(key, value)
            else:
                at = end
                while at - 1 > start and not lines[at - 1].strip():
                    at -= 1
                lines.insert(at, '{0} = {1}'.format(key, value))
                end += 1

    with open(path, 'w', newline='') as f:
        f.write(nl.join(lines) + nl)
