#!/usr/bin/env python3
"""Genera los archivos derivados de rules.json y viewer/:

  supout-viewer.html  visor autocontenido (template.html + engine.js + rules.json en un solo archivo)
  docs/REGLAS.md      catálogo de reglas, para leer sin abrir el JSON

Ejecutar después de editar rules.json o cualquier archivo de viewer/.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

SCOPES = [
    ("crash", "Crashes del kernel (cada volcado de la sección `oops`)"),
    ("backtrace", "Crashes de procesos y WinBox (cada evento de la sección `backtrace`)"),
    ("log", "Log del equipo (sección `log`, completa)"),
    ("debug", "Registro interno (sección `.debug`, completa)"),
    ("oops", "Mensajes del kernel previos a los crashes (sección `oops`, completa)"),
    ("routerboard", "Hardware y firmware (sección `routerboard`)"),
    ("export", "Configuración (sección `export`, normalizada)"),
]
SEV = {"critical": "crítico", "high": "alto", "medium": "medio", "low": "bajo", "info": "info"}


def read(*p):
    with open(os.path.join(HERE, *p), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    full = os.path.join(HERE, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(text)
    return full


def md_escape(s):
    return (s or "").replace("|", "\\|").replace("_", "\\_").replace("\n", " ")


def rules_doc(rules):
    out = ["# Catálogo de reglas", "",
           "> Generado por `build_viewer.py` a partir de `rules.json`. No editar a mano.", "",
           f"Total: **{len(rules)} reglas**. Formato de cada regla: ver [CONTRIBUIR.md](CONTRIBUIR.md#formato-de-una-regla).", ""]
    for scope, title in SCOPES:
        rs = [r for r in rules if r["scope"] == scope]
        if not rs:
            continue
        out += [f"## {title}", ""]
        groups = sorted({r["group"] for r in rs if r.get("group")})
        if groups:
            out += [f"Dentro de cada objetivo solo se aplica la primera regla que coincide de cada grupo "
                    f"({', '.join('`' + g + '`' for g in groups)}), en el orden de esta tabla.", ""]
        out += ["| Regla | Severidad | Título | Condiciones |", "|---|---|---|---|"]
        for r in rs:
            cond = []
            if r.get("group"):
                cond.append(f"grupo `{r['group']}`")
            if r.get("requires"):
                cond.append("requiere " + ", ".join(f"`{x}`" for x in r["requires"]))
            if r.get("min_count"):
                cond.append(f"mín. {r['min_count']} apariciones")
            if r.get("min_ratio"):
                cond.append(f"≥ {int(r['min_ratio'] * 100)} % de las líneas")
            if r.get("version_lt"):
                cond.append("compara versiones")
            title = md_escape(r["title"])
            if r.get("doc"):
                title += f" ([manual]({re.sub(r'[.]md$', '', r['doc'])}))"
            out.append(f"| `{r['id']}` | {SEV[r['severity']]} | {title} | {'; '.join(cond)} |")
        out.append("")
    out += ["## Hallazgos calculados en el código", "",
            "Estos no están en `rules.json` porque necesitan comparar varios eventos entre sí. "
            "Están implementados igual en `supout.py` y `viewer/engine.js`.", "",
            "| Id | Qué detecta |", "|---|---|",
            "| `file-truncated` | Archivo cortado en el medio de una sección, o terminado antes de `resource`. |",
            "| `crash-same-time` | Dos o más crashes del kernel con la misma hora exacta: reinicios distintos con fecha no confiable. |",
            "| `many-processes` | Cinco o más procesos distintos caídos: apunta a una causa común (versión, memoria, almacenamiento). |",
            ""]
    return "\n".join(out)


rules = json.loads(read("rules.json"))  # valida el JSON
html = (read("viewer", "template.html")
        .replace("/*__ENGINE__*/", read("viewer", "engine.js"))
        .replace("/*__RULES__*/", json.dumps(rules, ensure_ascii=False).replace("</", "<\\/")))
out = write("supout-viewer.html", html)
print(f"Generado {out} ({len(html):,} bytes, {len(rules['rules'])} reglas)")
doc = write(os.path.join("docs", "REGLAS.md"), rules_doc(rules["rules"]))
print(f"Generado {doc}")
