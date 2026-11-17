#!/usr/bin/env python3
"""Casos de regresión: extractos chicos de supouts reales para verificar que las reglas no se rompan.

  python3 tests/regresion.py agregar archivo.rif nombre-del-caso   # guarda tests/casos/<nombre>.json
  python3 tests/regresion.py correr                                 # verifica todos los casos
  python3 tests/regresion.py aceptar                                # toma lo obtenido como esperado
  python3 tests/regresion.py anonimizar                             # vuelve a anonimizar los casos guardados

Cada caso guarda solo las secciones del crash (oops, backtrace, resource, package, routerboard con el
número de serie enmascarado), el bloque @backtrace@ de .debug, las líneas de reinicio del log y el resultado
esperado. No incluye configuración ni log completo, y se anonimiza: el nombre del equipo, las IPv4
(reemplazadas por direcciones de documentación, RFC 5737) y los textos de los mensajes internos. Así los
.rif originales se pueden borrar y los casos se pueden publicar. Después de cambiar una regla a propósito,
volver a 'agregar' el caso afectado (o usar 'aceptar') para actualizar lo esperado.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import supout  # noqa: E402

CASES = os.path.join(HERE, "casos")
KEEP = ("oops", "backtrace", "resource", "package", "routerboard", ".debug", "log")  # .debug: solo @backtrace@; log: solo reinicios


IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")


def anonimizar(text, ips):
    """Quita datos identificables de un extracto: nombre del equipo, IPv4, textos de mensajes internos.
    `ips` es un dict compartido para que una misma IP se reemplace siempre por la misma dirección de
    documentación (RFC 5737)."""
    text = re.sub(r"\bLinux .+? (\d+\.\d+\.\d+\S*) #", r"Linux EQUIPO \1 #", text)
    text = re.sub(r"(\bstring \[[^\]\n]*\]=)[^\n]+", r"\1(texto)", text)

    def ip(m):
        addr = m.group(0)
        if addr in ("0.0.0.0", "255.255.255.255") or int(m.group(1)) == 127:
            return addr
        if addr not in ips:
            n = len(ips)
            ips[addr] = f"{('192.0.2', '198.51.100', '203.0.113')[n // 254 % 3]}.{n % 254 + 1}"
        return ips[addr]
    return IPV4.sub(ip, text)


def extract(sections):
    out = []
    for name, text, truncated in sections:
        if name not in KEEP:
            continue
        if name == ".debug":
            m = re.search(r"^@backtrace@[ \t]*\n.*?(?=^@[\w.-]+@[ \t]*$|\Z)", text, re.M | re.S)
            if m:
                out.append({"name": name, "text": "\n".join(m.group(0).split("\n")[:300]), "truncated": False})
            continue
        if name == "log":  # solo líneas de reinicio/watchdog, sin datos de clientes
            keep = [l for l in text.split("\n") if re.search(r"reboot|watchdog|kernel failure|proper shutdown", l, re.I)]
            out.append({"name": name, "text": "\n".join(keep), "truncated": False})
            continue
        if name == "routerboard":
            text = re.sub(r"(serial-number: ).*", r"\1XXXXXXXXXXX", text)
        out.append({"name": name, "text": text, "truncated": truncated})
    ips = {}
    for s in out:
        s["text"] = anonimizar(s["text"], ips)
    if any(t for _, _, t in sections):  # conservar la marca de archivo truncado
        out.append({"name": next(n for n, _, t in sections if t), "text": "", "truncated": True})
    return out


def summary(r):
    ids = lambda fs: [f["id"] for f in fs]
    return {
        "model": r["device"]["model"], "version": r["device"]["version"],
        "trigger": r["trigger"]["kind"], "trigger_title": r["trigger"]["title"],
        "general": ids(r["general_findings"]),
        "crashes": [{"time": c["time"], "rules": ids(c["findings"]), "functions": c["functions"][:4]} for c in r["crashes"]],
        "events": [[e["time"], ids(e["findings"])] for e in r["backtraces"]],
    }


def run_case(case):
    secs = [(s["name"], s["text"], s["truncated"]) for s in case["sections"]]
    return summary(supout.analyze_sections(case["name"], secs))


def add(path, name):
    sections = supout.read_sections(path)
    case = {"name": name, "sections": extract(sections)}
    case["expected"] = run_case(case)
    full = summary(supout.analyze(path))
    for k in ("trigger", "crashes", "events", "general"):
        if full[k] != case["expected"][k]:
            print(f"  aviso: '{k}' depende de secciones que no se guardan (log/config); el caso no lo cubre igual")
    os.makedirs(CASES, exist_ok=True)
    dst = os.path.join(CASES, name + ".json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(case, f, ensure_ascii=False, indent=1)
    print(f"Guardado {dst} ({os.path.getsize(dst) // 1024} KB): {case['expected']['trigger_title']}")


def run(accept=False):
    files = sorted(f for f in os.listdir(CASES) if f.endswith(".json"))
    fails = 0
    for fn in files:
        p = os.path.join(CASES, fn)
        case = json.load(open(p, encoding="utf-8"))
        got = run_case(case)
        if got == case["expected"]:
            print(f"OK    {case['name']}")
            continue
        fails += 1
        print(f"FALLA {case['name']}")
        for k in case["expected"]:
            if got.get(k) != case["expected"][k]:
                print(f"   {k}:\n     esperado {json.dumps(case['expected'][k], ensure_ascii=False)[:300]}\n     obtenido {json.dumps(got.get(k), ensure_ascii=False)[:300]}")
        if accept:
            case["expected"] = got
            json.dump(case, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print("   → aceptado como nuevo esperado")
    print(f"\n{len(files) - fails}/{len(files)} casos OK")
    return fails


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "agregar":
        add(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 2 and sys.argv[1] == "anonimizar":
        for p in sorted(os.listdir(CASES)):
            path = os.path.join(CASES, p)
            case = json.load(open(path, encoding="utf-8"))
            ips = {}
            for sec in case["sections"]:
                sec["text"] = anonimizar(sec["text"], ips)
            case.pop("source", None)
            json.dump(case, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print(f"anonimizado {p} ({len(ips)} IPs)")
    elif len(sys.argv) == 2 and sys.argv[1] in ("correr", "aceptar"):
        sys.exit(1 if run(accept=sys.argv[1] == "aceptar") and sys.argv[1] == "correr" else 0)
    else:
        print(__doc__)
