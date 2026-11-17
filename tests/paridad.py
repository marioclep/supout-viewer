#!/usr/bin/env python3
"""Verifica que la CLI (supout.py) y el visor (viewer/engine.js) den el mismo diagnóstico.

  python3 tests/paridad.py                 # todos los casos de tests/casos/
  python3 tests/paridad.py archivo.rif ... # además, archivos .rif completos

Corre engine.js con un intérprete de JavaScript de línea de comandos: Node.js si está instalado,
o JavaScriptCore (jsc), que viene con macOS. Compara motivo del supout, hallazgos generales,
crashes, eventos, log, configuración y líneas críticas del log.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import supout  # noqa: E402

JSC = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"

JS_SUMMARY = """
var r = SupoutEngine.analyze("x", SECTIONS, RULES.rules);
function t(L) { return L.map(function (x) { return x.title + "|" + x.detail + "|" + String(x.doc || null).replace("null", "None"); }); }
OUT(JSON.stringify({
  trigger: [r.trigger.kind, r.trigger.title, r.trigger.detail],
  general: t(r.general_findings),
  crashes: r.crashes.map(function (c) { return t(c.findings); }),
  bt: r.backtraces.map(function (b) { return [b.time, t(b.findings)]; }),
  log: t(r.log_findings).sort(), cfg: t(r.config_findings).sort(), crit: r.critical_log
}));
"""


def find_js():
    node = shutil.which("node")
    if node:
        return [node], "console.log"
    if os.path.exists(JSC):
        return [JSC], "print"
    sys.exit("No se encontró un intérprete de JavaScript (instalar Node.js, o usar macOS con JavaScriptCore).")


def py_summary(r):
    t = lambda L: [f"{x['title']}|{x['detail']}|{x.get('doc') or None}" for x in L]
    return {"trigger": [r["trigger"]["kind"], r["trigger"]["title"], r["trigger"]["detail"]],
            "general": t(r["general_findings"]), "crashes": [t(c["findings"]) for c in r["crashes"]],
            "bt": [[b["time"], t(b["findings"])] for b in r["backtraces"]],
            "log": sorted(t(r["log_findings"])), "cfg": sorted(t(r["config_findings"])), "crit": r["critical_log"]}


def js_summary(cmd, out_fn, sections, rules, tmp):
    src = (open(os.path.join(ROOT, "viewer", "engine.js"), encoding="utf-8").read()
           + "\nvar OUT = " + out_fn + ";\nvar RULES = " + json.dumps(rules) + ";\nvar SECTIONS = "
           + json.dumps([{"name": n, "text": t, "truncated": tr} for n, t, tr in sections]) + ";\n" + JS_SUMMARY)
    path = os.path.join(tmp, "paridad.js")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    res = subprocess.run(cmd + [path], capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(res.stderr.strip() or "sin salida")
    return json.loads(res.stdout)


def main():
    cmd, out_fn = find_js()
    rules = json.load(open(os.path.join(ROOT, "rules.json"), encoding="utf-8"))
    sources = [(p, "caso") for p in sorted(glob.glob(os.path.join(HERE, "casos", "*.json")))]
    sources += [(p, "rif") for p in sys.argv[1:]]
    fails = 0
    with tempfile.TemporaryDirectory() as tmp:
        for path, kind in sources:
            if kind == "caso":
                sections = [(s["name"], s["text"], s["truncated"]) for s in json.load(open(path, encoding="utf-8"))["sections"]]
            else:
                sections = supout.read_sections(path)
            py = py_summary(supout.analyze_sections(os.path.basename(path), sections, rules["rules"]))
            try:
                js = js_summary(cmd, out_fn, sections, rules, tmp)
            except RuntimeError as e:
                print(f"ERROR {os.path.basename(path)}: {e}")
                fails += 1
                continue
            diff = [k for k in py if json.dumps(py[k], sort_keys=True) != json.dumps(js.get(k), sort_keys=True)]
            print(("OK    " if not diff else "DIFF  ") + os.path.basename(path) + (f"  {diff}" if diff else ""))
            for k in diff:
                print(f"   {k}:\n     py {json.dumps(py[k], ensure_ascii=False)[:400]}\n     js {json.dumps(js.get(k), ensure_ascii=False)[:400]}")
            fails += bool(diff)
    print(f"\n{len(sources) - fails}/{len(sources)} iguales")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
