#!/usr/bin/env python3
"""Decodificador y diagnóstico de archivos supout.rif / autosupout.rif de MikroTik RouterOS.

Uso:
  python3 supout.py archivo.rif                 # informe de diagnóstico
  python3 supout.py archivo.rif --json          # diagnóstico en JSON
  python3 supout.py archivo.rif --list          # lista de secciones
  python3 supout.py archivo.rif --show log      # imprime una sección
  python3 supout.py archivo.rif --extract DIR   # guarda todas las secciones como .txt

Solo usa la biblioteca estándar de Python 3.8+. Las reglas están en rules.json.
"""
import argparse
import calendar
import json
import os
import re
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64_IDX = {c: i for i, c in enumerate(B64)}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------- decodificación

def mt_b64decode(s):
    """Base64 de MikroTik: mismo alfabeto, pero los bits van en orden little-endian."""
    s = re.sub(r"\s", "", s)
    out = bytearray()
    for i in range(0, len(s), 4):
        o = n = 0
        for j, c in enumerate(s[i:i + 4]):
            if c == "=":
                break
            o |= B64_IDX[c] << (6 * j)
            n += 1
        for k in range({2: 1, 3: 2, 4: 3}.get(n, 0)):
            out.append((o >> (8 * k)) & 0xFF)
    return bytes(out)


BEGIN, END = "--BEGIN ROUTEROS SUPOUT SECTION", "--END ROUTEROS SUPOUT SECTION"


def read_sections(path):
    """Devuelve [(nombre, texto, truncada)] en el orden del archivo.
    Si el archivo está cortado, recupera lo que se pueda de la última sección y la marca como truncada."""
    with open(path, encoding="ascii", errors="replace") as f:
        txt = f.read()
    sections = []
    for block in txt.split(BEGIN)[1:]:
        complete = END in block
        raw = mt_b64decode(block.split(END)[0])
        nul = raw.find(b"\0")
        if nul < 0:
            continue
        name, data = raw[:nul].decode("latin1"), raw[nul + 1:]
        d = zlib.decompressobj()
        try:
            out = d.decompress(data)
            truncated = not complete or (len(data) > 0 and not d.eof)
        except zlib.error:
            out, truncated = data, not complete  # sección sin comprimir o ilegible: se deja tal cual
        sections.append((name, out.decode("utf-8", errors="replace").replace("\r\n", "\n"), truncated))
    if not sections:
        raise ValueError("No se encontraron secciones: ¿es un archivo supout.rif?")
    return sections


# ---------------------------------------------------------------- parsers

def first(pattern, text, default=None, flags=re.M):
    m = re.search(pattern, text or "", flags)
    return m.group(1).strip() if m else default


def fmt_uptime(seconds):
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (f"{d}d " if d else "") + f"{h:02}:{m:02}:{s:02}"


def parse_ros_uptime(s):
    """'1w6d11h13m9s' -> segundos."""
    if not s:
        return None
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    parts = re.findall(r"(\d+)([wdhms])", s)
    return sum(int(n) * units[u] for n, u in parts) if parts else None


def normalize_export(text):
    """Une líneas continuadas con '\\' y antepone la ruta (/ip firewall filter ...) a cada add/set."""
    lines, buf = [], ""
    for line in text.split("\n"):
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        lines.append(buf + line.strip() if buf else line)
        buf = ""
    out, cur = [], ""
    for line in lines:
        if line.startswith("/"):
            cur = line.strip()
            out.append(cur)
        elif line.strip() and not line.lstrip().startswith("#"):
            out.append(cur + " " + line.strip())
    return "\n".join(out)


def parse_crashes(oops):
    """Divide la sección oops en eventos ('--- N' ... '--- rebooted')."""
    crashes = []
    parts = re.split(r"^--- (\d+)\s*$", oops or "", flags=re.M)
    for idx in range(1, len(parts), 2):
        body = re.sub(r"^--- rebooted\s*$", "", parts[idx + 1], flags=re.M).strip()
        stamps = re.findall(r"^(?:DUMP: )?\[\s*(\d+\.\d+)\]", body, re.M)
        msgs = {}
        for line in body.split("\n"):
            msg = re.sub(r"^(?:DUMP: )?(?:\[[^\]]*\](?:\[[^\]]*\])?\s*)?(?:<\d>)?\s*", "", line).strip()
            if msg and not msg.startswith("_stext"):
                msgs[msg] = msgs.get(msg, 0) + 1
        funcs = []
        for fn in re.findall(r"\b([A-Za-z_]\w*)\+0x[0-9a-f]+/0x[0-9a-f]+", body):
            if fn != "_stext" and fn not in funcs:
                funcs.append(fn)
        crashes.append({
            "index": int(parts[idx]),
            "version": first(r"^v(\S+)", body),
            "time": first(r"^v\S+ .* at (\S+)", body),
            "uptime": fmt_uptime(float(stamps[-1])) if stamps else None,
            "panic": first(r"Kernel panic - not syncing: (.*)$", body),
            "process": first(r"(?:stuck for \d+s! \[|Comm: |comm:\s+)([^\]\s,]+)", body),
            "functions": funcs[:6],
            "workqueue": first(r"Workqueue: \S+ (\S+)", body),
            "modules": sorted(set(re.findall(r"\[(\w+)@0x", body))),
            "repeated": [{"msg": k, "count": v} for k, v in sorted(msgs.items(), key=lambda x: -x[1]) if v >= 3][:3],
            "text": body,
        })
    return crashes


EVENT_START = r"^\S+@\d+: (?:/\S+|WinBox|had panic)[ \t]*$"


def parse_backtraces(bt):
    """Divide la sección backtrace en eventos (crash de proceso, panic, WinBox), cada uno con su bloque de arranque."""
    events = []
    for m in re.finditer(r"^---- (\w+) v(\S+) (.+?) ----\s*$\n(.*?)(?=^---- \w+ v|\Z)", bt or "", re.M | re.S):
        body = m.group(4).strip()
        if not body:
            continue
        starts = [s.start() for s in re.finditer(EVENT_START, body, re.M)] or [0]
        starts[0] = 0
        for i, st in enumerate(starts):
            text = body[st:starts[i + 1] if i + 1 < len(starts) else len(body)].strip()
            events.append({"boot": m.group(1), "version": m.group(2),
                           "time": first(r"^(\S+?)(?:\.\d+)?@", text), "text": text})
    return events


def debug_backtrace(debug):
    """El bloque @backtrace@ de .debug guarda el último crash que procesó RouterOS (el que generó el autosupout).
    Devuelve (hora, texto) o None. Si todavía no llegó a la sección backtrace, se agrega como evento pendiente."""
    m = re.search(r"^@backtrace@[ \t]*\n(.*?)(?=^@[\w.-]+@[ \t]*$|\Z)", debug or "", re.M | re.S)
    if not m or not re.search(r"backtrace: 0x|had panic|WinBox|--- signal=", m.group(1)):
        return None
    text = m.group(1).strip()
    t = first(r"^(\d{4}\.\d\d\.\d\d-\d\d:\d\d:\d\d)", text)
    return (t, text) if t else None


def device_info(sec):
    res, rb, exp = sec.get("resource", ""), sec.get("routerboard", ""), sec.get("export", "")
    ppp = sec.get("ppp", "")
    return {
        "identity": first(r'^/system identity\s*\nset name="?([^"\n]+)', exp),
        "model": first(r"^\s*model: (.+)$", rb) or first(r"^\s*board-name: (.+)$", res),
        "serial": first(r"^\s*serial-number: (.+)$", rb),
        "version": first(r"^\s*version: (.+)$", res),
        "firmware": first(r"^\s*current-firmware: (.+)$", rb),
        "uptime": first(r"^\s*uptime: (\S+)", res),
        "date": " ".join(filter(None, [first(r"^\s*date: (\S+)", res), first(r"^\s*time: (\S+)", res)])) or None,
        "timezone": first(r"^\s*time-zone-name: (\S+)", res),
        "gmt_offset": first(r"^\s*gmt-offset: ([+-]\d\d:\d\d)", res),
        "memory": " / ".join(filter(None, [first(r"^\s*free-memory: (\S+)", res), first(r"^\s*total-memory: (\S+)", res)])) or None,
        "cpu": " ".join(filter(None, [first(r"^\s*cpu-count: (\S+)", res), "x", first(r"^\s*cpu-frequency: (\S+)", res)])),
        "ppp_active": len(re.findall(r"^\s*\d+\s+\S*\s*name=", ppp, re.M)) if ppp else None,
    }


# ---------------------------------------------------------------- motor de reglas

def load_rules(path=None):
    with open(path or os.path.join(HERE, "rules.json"), encoding="utf-8") as f:
        return json.load(f)["rules"]


def fill(template, count, groups):
    def rep(m):
        if m.group(1) == "count":
            return str(count)
        i = int(m.group(1))
        return (groups[i] or "") if i < len(groups) else ""
    return re.sub(r"\{(count|\d+)\}", rep, template or "")


def version_key(v):
    return [int(x) for x in re.findall(r"\d+", v or "")]


MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]


def supout_epoch(device):
    """Hora UTC (epoch) en que se generó el supout, a partir de date/time y gmt-offset de resource."""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$", device.get("date") or "")
    if m:
        y, mo, d, hh, mi, ss = map(int, m.groups())
    else:
        m = re.match(r"([a-z]{3})/(\d\d)/(\d{4}) (\d\d):(\d\d):(\d\d)$", (device.get("date") or "").lower())
        if not m or m.group(1) not in MONTHS:
            return None
        mo, (d, y, hh, mi, ss) = MONTHS.index(m.group(1)) + 1, map(int, m.groups()[1:])
    off = re.match(r"([+-])(\d\d):(\d\d)$", device.get("gmt_offset") or "")
    if not off:
        return None
    sign = -1 if off.group(1) == "-" else 1
    return calendar.timegm((y, mo, d, hh, mi, ss)) - sign * (int(off.group(2)) * 3600 + int(off.group(3)) * 60)


def event_epoch(t):
    """'2026.05.29-10:45:58' (UTC, como en backtrace) → epoch."""
    m = re.match(r"(\d{4})\.(\d\d)\.(\d\d)-(\d\d):(\d\d):(\d\d)$", t or "")
    return calendar.timegm(tuple(map(int, m.groups()))) if m else None


TRIGGER_LAG = 300  # el autosupout se escribe segundos después del evento que lo genera


def apply_rule(rule, text, fired):
    if rule.get("requires") and not any(r in fired for r in rule["requires"]):
        return None
    flags = re.M | (re.I if rule.get("icase") else 0)
    m0, count = None, 0
    for i, pat in enumerate(rule["match"]):
        m = re.search(pat, text, flags)
        if not m:
            return None
        if i == 0:
            m0, count = m, len(re.findall(pat, text, flags))
    if any(re.search(p, text, flags) for p in rule.get("not", [])):
        return None
    if rule.get("version_lt"):
        a, b = (version_key(m0.group(i)) for i in rule["version_lt"])
        if not a < b:
            return None
    if count < rule.get("min_count", 1):
        return None
    if rule.get("min_ratio") and count / max(1, len([l for l in text.split("\n") if l.strip()])) < rule["min_ratio"]:
        return None
    groups = [m0.group(0)] + list(m0.groups())
    return {k: (fill(rule.get(k), count, groups) if k in ("title", "detail", "recommend") else rule.get(k))
            for k in ("id", "severity", "title", "detail", "recommend", "doc")}


def run_rules(rules, scope, targets, fired):
    """targets: lista de textos; devuelve lista de listas de hallazgos (una por objetivo)."""
    results = []
    for text in targets:
        found, used_groups = [], set()
        for rule in (r for r in rules if r["scope"] == scope):
            if rule.get("group") and rule["group"] in used_groups:
                continue
            f = apply_rule(rule, text, fired)
            if f:
                found.append(f)
                fired.add(f["id"])
                if rule.get("group"):
                    used_groups.add(rule["group"])
        results.append(found)
    return results


def same_time_findings(crashes):
    """Varios volcados con la misma hora exacta: son reinicios distintos pero la fecha no es real."""
    counts = {}
    for c in crashes:
        if c.get("time"):
            counts[c["time"]] = counts.get(c["time"], 0) + 1
    return [{"id": "crash-same-time", "severity": "medium",
             "title": f"{n} crashes del kernel con la misma hora exacta ({t})",
             "detail": "Son reinicios distintos (cada volcado termina en su propio «rebooted»), pero quedaron con la misma "
                       "marca de tiempo. La hora sale del reloj del equipo, y si no estaba en hora (por ejemplo, antes de "
                       "sincronizar por NTP) la fecha no es real. Contalos como reinicios separados de fecha desconocida.",
             "recommend": "Verificar que NTP esté configurado (`/system ntp client`). Para saber cuándo ocurrieron, cruzar con el monitoreo externo (caídas de ping, sesiones BGP o PPP).",
             "doc": "https://manual.mikrotik.com/docs/cli-reference/system/ntp/client.md"}
            for t, n in counts.items() if n >= 2]


def many_processes_findings(events, minimum=5):
    """Muchos procesos distintos caídos: apunta a una causa común (versión, memoria, almacenamiento)."""
    names = []
    for e in events:
        n = first(r"@\d+: /\S*?([^/\s]+)\s*\n[^\n]*--- signal=", e["text"])
        if n and n not in names:
            names.append(n)
    if len(names) < minimum:
        return []
    return [{"id": "many-processes", "severity": "medium",
             "title": f"Se cayeron {len(names)} procesos distintos ({', '.join(names)})",
             "detail": "Cuando fallan muchos procesos distintos, y no siempre el mismo, lo más probable es una causa común y no un bug de cada proceso: errores de la versión de RouterOS corregidos más adelante, falta de memoria o, menos seguido, almacenamiento o RAM con fallas.",
             "recommend": "Actualizar a la última versión long-term. Si sigue pasando, verificar el almacenamiento con `/system check-installation` y revisar la memoria libre.",
             "doc": "https://manual.mikrotik.com/docs/cli-reference/system/check-installation.md"}]


REBOOT_WINDOW = 1800  # un autosupout escrito tras un crash se genera en los primeros minutos del arranque


def supout_trigger(device, crashes, events, log_findings):
    """Deduce qué generó este supout: un crash del kernel (reinicio), la caída de un proceso, u otra cosa."""
    up = parse_ros_uptime(device.get("uptime"))
    s_ep = supout_epoch(device)
    cur = [e for e in events if e["boot"] == "current" and e.get("findings")]
    procs = [e for e in cur if e["findings"][0]["id"].startswith("bt-process")]
    near = [e for e in cur if s_ep is not None and event_epoch(e["time"]) is not None
            and 0 <= s_ep - event_epoch(e["time"]) <= TRIGGER_LAG]
    trig = max(near, key=lambda e: e["time"]) if near else None
    lag = s_ep - event_epoch(trig["time"]) if trig else None
    if up is None:
        trig = next((e for e in cur if e.get("debug_last")), None)
        from_debug = bool(trig)
        if not trig and procs:
            trig = max(procs, key=lambda e: e["time"] or "")
        if not trig:
            return {"kind": "unknown", "title": "No se pudo determinar qué generó este supout",
                    "detail": "Falta la sección resource (uptime) y no hay un crash reciente registrado."}
    elif up <= REBOOT_WINDOW:
        extra = ""
        if trig and trig["findings"][0]["id"] != "bt-panic":
            extra = (f" El autosupout en sí lo escribió un evento posterior al arranque, {lag} s antes del supout: "
                     f"{trig['findings'][0]['title']}.")
        if crashes:
            return {"kind": "kernel-crash", "title": "Reinicio por un crash del kernel",
                    "detail": f"El supout se generó con {device['uptime']} de uptime, justo después de arrancar, e incluye el volcado del crash." + extra}
        if any(f["id"] == "log-unclean" for f in log_findings):
            return {"kind": "unclean", "title": "Reinicio sin apagado ordenado y sin crash del kernel registrado",
                    "detail": "No hay volcado en la sección oops. Suele indicar un corte de energía, un reset por hardware o un cuelgue que no alcanzó a registrarse." + extra}
        if not extra:
            return {"kind": "boot", "title": "Supout generado poco después de un arranque, sin crash registrado",
                    "detail": f"Uptime {device['uptime']}. Puede ser un reinicio ordenado o un supout generado a mano."}
    elif not trig:
        if procs and s_ep is not None:
            last = max(procs, key=lambda e: e["time"] or "")
            return {"kind": "manual", "title": "El router no se reinició y no se encontró el evento que generó el supout",
                    "detail": f"Llevaba {device['uptime']} encendido. La última caída de un proceso en este arranque "
                              f"({last['findings'][0]['title']}, {last['time']}) fue bastante antes del supout, así que no lo "
                              "explica. Puede haberse generado a mano (/system/sup-output) o por un evento que no quedó registrado."}
        if procs:
            last = max(procs, key=lambda e: e["time"] or "")
            return {"kind": "process", "title": "El router no se reinició: " + last["findings"][0]["title"],
                    "detail": f"Llevaba {device['uptime']} encendido. Cuando un proceso de RouterOS se cae, el sistema lo vuelve a "
                              f"levantar y guarda un autosupout sin reiniciar el equipo. Última caída: {last['time']}.",
                    "event_time": last["time"]}
        return {"kind": "manual", "title": "El router no se reinició y no hay un crash que explique el supout",
                "detail": f"Llevaba {device['uptime']} encendido. Probablemente se generó a mano (/system/sup-output)."}

    f = trig["findings"][0]
    if up is None:
        prefix = "Probablemente: "
        head = "No se pudo leer el uptime (falta la sección resource), así que no se sabe si el equipo se reinició. "
        when = (f"Según el registro interno (.debug), es el último crash que procesó RouterOS ({trig['time']})." if from_debug
                else f"Es la última caída registrada en el arranque actual ({trig['time']}).")
    elif up <= REBOOT_WINDOW:
        prefix = ""
        head = (f"Llevaba {device['uptime']} encendido: el equipo había arrancado hacía poco, sin crash registrado, "
                "pero el supout no salió del arranque. ")
        when = f"Se escribió {lag} s después ({trig['time']})."
    else:
        prefix = "El router no se reinició: "
        head = f"Llevaba {device['uptime']} encendido. "
        when = f"Se escribió {lag} s después ({trig['time']})."
    if f["id"] == "bt-winbox":
        wb = first(r"winbox version: ?(\S+)", trig["text"]) or ""
        return {"kind": "winbox", "title": prefix + ("lo" if prefix else "Lo") + " generó un crash de WinBox en una PC",
                "detail": head + f"El autosupout salió del reporte de un crash de WinBox {wb} enviado desde una PC. " + when,
                "event_time": trig["time"]}
    if f["id"].startswith("bt-process"):
        return {"kind": "process", "title": prefix + f["title"],
                "detail": head + "Cuando un proceso de RouterOS se cae, el sistema lo vuelve a levantar y guarda un "
                                 "autosupout sin reiniciar el equipo. " + when,
                "event_time": trig["time"]}
    if f["id"] == "bt-panic" and up is None:
        return {"kind": "kernel-crash", "title": "Probablemente: reinicio por un crash del kernel",
                "detail": head + "El último evento que procesó RouterOS fue un kernel panic. " + when}
    return {"kind": "manual", "title": "No se pudo determinar qué generó este supout", "detail": head.strip()}


def analyze(path, rules=None):
    return analyze_sections(os.path.basename(path), read_sections(path), rules)


def analyze_sections(file_name, sections, rules=None):
    """sections: [(nombre, texto, truncada)]."""
    rules = rules or load_rules()
    sec = {}
    for name, text, _ in sections:
        sec.setdefault(name, text)
    fired = set()
    crashes = parse_crashes(sec.get("oops"))
    for c, f in zip(crashes, run_rules(rules, "crash", [c["text"] for c in crashes], fired)):
        c["findings"] = f
    bts = parse_backtraces(sec.get("backtrace"))
    dbt = debug_backtrace(sec.get(".debug"))
    if dbt:
        same = [e for e in bts if e["time"] == dbt[0]]
        if same:
            same[-1]["debug_last"] = True
        else:
            bts.append({"boot": "current", "version": first(r"^\s*version: (\S+)", sec.get("resource", "")) or "?",
                        "time": dbt[0], "text": dbt[1], "pending": True, "debug_last": True})
    for b, f in zip(bts, run_rules(rules, "backtrace", [b["text"] for b in bts], fired)):
        b["findings"] = f
    log_f = run_rules(rules, "log", [sec.get("log", "")], fired)[0]
    log_f += run_rules(rules, "debug", [sec.get(".debug", "")], fired)[0]
    log_f += run_rules(rules, "oops", [sec.get("oops", "")], fired)[0]
    device = device_info(sec)
    if not device["version"]:  # archivo incompleto: tomar la versión del arranque actual en backtrace
        device["version"] = next((e["version"] for e in bts if e["boot"] == "current" and not e.get("pending")), None)
    general = [{"id": "file-truncated", "severity": "high",
                "title": f"Archivo incompleto: se corta en la sección «{n}»",
                "detail": "Faltan las secciones siguientes (log, configuración, etc.). Pasa si el router se reinició o se quedó "
                          "sin memoria mientras generaba el archivo, o si la descarga/copia quedó incompleta. "
                          "Se analizó lo que se pudo recuperar.",
                "recommend": "Si el archivo original en el router está completo, volver a descargarlo.", "doc": None}
               for n, _, t in sections if t]
    general += run_rules(rules, "routerboard", [sec.get("routerboard", "")], fired)[0]
    if not any(t for _, _, t in sections) and sections and "resource" not in sec:
        general.append({"id": "file-truncated", "severity": "high",
                        "title": f"Archivo incompleto: termina después de la sección «{sections[-1][0]}»",
                        "detail": "Faltan las secciones siguientes (resource, log, configuración, etc.), así que no hay datos del "
                                  "equipo ni uptime. Pasa si el router se reinició o se quedó sin memoria mientras generaba el "
                                  "archivo, o si la descarga/copia quedó incompleta. Se analizó lo que se pudo recuperar.",
                        "recommend": "Si el archivo original en el router está completo, volver a descargarlo.", "doc": None})
    general += same_time_findings(crashes)
    general += many_processes_findings(bts)
    cfg_f = run_rules(rules, "export", [normalize_export(sec.get("export", ""))], fired)[0]
    critical_log = [l for l in sec.get("log", "").split("\n") if re.search(r",(critical|error)\b", l) and "pppoe" not in l][:50]
    return {
        "file": file_name,
        "device": device,
        "trigger": supout_trigger(device, crashes, bts, log_f),
        "general_findings": general,
        "crashes": crashes,
        "backtraces": bts,
        "log_findings": log_f,
        "config_findings": cfg_f,
        "critical_log": critical_log,
        "health": sec.get("health", "").strip(),
        "sections": [{"name": n, "size": len(t), "truncated": tr} for n, t, tr in sections],
    }


# ---------------------------------------------------------------- salida

COLORS = {"critical": "\033[1;41;97m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
LABEL = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO", "low": "BAJO", "info": "INFO"}


def render_text(r, color=True):
    c = (lambda sev, s: f"{COLORS[sev]}{s}\033[0m") if color else (lambda sev, s: s)
    bold = (lambda s: f"\033[1m{s}\033[0m") if color else (lambda s: s)
    out = []
    d = r["device"]
    out.append(bold(f"═══ {r['file']} ═══"))
    out.append(f"Equipo:   {d['identity'] or '-'} · {d['model'] or '-'} · S/N {d['serial'] or '-'}")
    out.append(f"RouterOS: {d['version'] or '-'} (firmware {d['firmware'] or '-'})")
    out.append(f"Supout:   {d['date'] or '-'} {d['timezone'] or ''} · uptime {d['uptime'] or '-'}"
               + (f" · {d['ppp_active']} sesiones PPP activas" if d['ppp_active'] is not None else ""))
    t = r["trigger"]
    out.append("")
    out.append(bold("► Motivo del supout: " + t["title"]))
    out.append("  " + t["detail"])

    def finding(f, indent="  "):
        out.append(indent + c(f["severity"], f"[{LABEL[f['severity']]}]") + " " + bold(f["title"]))
        if f.get("detail"):
            out.append(indent + "    " + f["detail"])
        if f.get("recommend"):
            out.append(indent + "    → " + f["recommend"])
        if f.get("doc"):
            out.append(indent + "    Manual: " + re.sub(r"\.md$", "", f["doc"]))

    for f in r["general_findings"]:
        out.append("")
        finding(f)
    out.append("")
    hist = r["trigger"]["kind"] != "kernel-crash" and r["crashes"]
    out.append(bold(f"■ Crashes del kernel ({len(r['crashes'])})" + (" — anteriores, no explican este supout" if hist else "")))
    if not r["crashes"]:
        out.append("  Sin eventos en la sección oops.")
    for cr in r["crashes"]:
        out.append(f"  #{cr['index']}  {cr['time'] or '?'} (hora del kernel)  ·  RouterOS {cr['version'] or '?'}"
                   f"  ·  uptime al crash {cr['uptime'] or '?'}")
        meta = []
        if cr["process"]: meta.append(f"proceso {cr['process']}")
        if cr["workqueue"]: meta.append(f"función {cr['workqueue']}")
        if cr["modules"]: meta.append("módulos " + ", ".join(cr["modules"]))
        if cr["functions"]: meta.append("funciones " + " ← ".join(cr["functions"][:4]))
        if meta: out.append("      " + " · ".join(meta))
        for rep in cr["repeated"]:
            out.append(f"      ×{rep['count']}  {rep['msg'][:110]}")
        for f in cr["findings"]:
            finding(f, "    ")
        out.append("")

    if r["backtraces"]:
        out.append(bold(f"■ Historial de fallas ({len(r['backtraces'])} eventos)"))
        for b in sorted(r["backtraces"], key=lambda b: b["time"] or "", reverse=True):
            title = b["findings"][0]["title"] if b["findings"] else "?"
            sev = b["findings"][0]["severity"] if b["findings"] else "info"
            now = " (arranque actual)" if b["boot"] == "current" else ""
            if b.get("pending"):
                now += " (solo en .debug: aún no estaba en backtrace)"
            out.append(f"  {b['time'] or '?':22} v{b['version']:10} " + c(sev, title) + now)
        out.append("")

    for label, items in (("■ Log y registros internos", r["log_findings"]), ("■ Configuración", r["config_findings"])):
        if items:
            out.append(bold(label))
            for f in sorted(items, key=lambda f: SEVERITY_ORDER.index(f["severity"])):
                finding(f)
            out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Diagnóstico de supout.rif de MikroTik RouterOS")
    ap.add_argument("files", nargs="+", help="archivo(s) .rif")
    ap.add_argument("--json", action="store_true", help="salida en JSON")
    ap.add_argument("--list", action="store_true", help="listar secciones")
    ap.add_argument("--show", metavar="SECCION", help="imprimir una sección")
    ap.add_argument("--extract", metavar="DIR", help="guardar todas las secciones en DIR")
    ap.add_argument("--rules", metavar="JSON", help="archivo de reglas alternativo")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()

    rules = load_rules(a.rules)
    for path in a.files:
        if a.list or a.show or a.extract:
            sections = read_sections(path)
            if a.list:
                for i, (n, t, tr) in enumerate(sections):
                    print(f"{i:3}  {n:24} {len(t):>10,} bytes" + ("  [TRUNCADA]" if tr else ""))
            if a.show:
                hits = [t for n, t, _ in sections if n == a.show]
                if not hits:
                    sys.exit(f"No existe la sección '{a.show}'. Usá --list.")
                print(hits[0])
            if a.extract:
                d = os.path.join(a.extract, os.path.splitext(os.path.basename(path))[0])
                os.makedirs(d, exist_ok=True)
                for i, (n, t, _) in enumerate(sections):
                    safe = re.sub(r"[^A-Za-z0-9._-]", "_", n) or "sin_nombre"
                    with open(os.path.join(d, f"{i:03}_{safe}.txt"), "w", encoding="utf-8") as f:
                        f.write(t)
                print(f"{len(sections)} secciones guardadas en {d}")
            continue
        r = analyze(path, rules)
        if a.json:
            for cr in r["crashes"]:
                cr.pop("text")
            print(json.dumps(r, ensure_ascii=False, indent=2))
        else:
            print(render_text(r, color=sys.stdout.isatty() and not a.no_color))


if __name__ == "__main__":
    main()
