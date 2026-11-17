# Cómo contribuir

## Flujo de trabajo con un supout nuevo

1. Copiar el `.rif` a `muestras/` (ignorada por git; puede tener subcarpetas por caso).
2. Analizarlo:
   ```sh
   python3 supout.py muestras/autosupout.rif
   python3 supout.py muestras/autosupout.rif --list          # secciones
   python3 supout.py muestras/autosupout.rif --show backtrace
   ```
3. Buscar lo que la herramienta **no** explica bien:
   - crashes que caen en las reglas genéricas (`panic-generic`, `kernel-bad-trap`, `bt-process`,
     `bt-process-signal`);
   - un "Motivo del supout" que no cierra con los datos (comparar horas y uptime);
   - mensajes repetidos en el log o en `oops` que nadie señala.
4. Verificar la interpretación en el [manual de MikroTik](https://manual.mikrotik.com)
   (`https://manual.mikrotik.com/llms.txt` es el índice; `llms-full.txt`, el manual completo en texto).
   Si no está documentado, la regla tiene que decirlo y usar severidad baja.
5. Escribir o ajustar reglas en `rules.json` (ver abajo).
6. Guardar el caso de regresión y verificar:
   ```sh
   python3 tests/regresion.py agregar muestras/autosupout.rif modelo-version-descripcion
   python3 build_viewer.py
   python3 tests/regresion.py correr
   python3 tests/paridad.py muestras/autosupout.rif
   ```
7. Revisar el extracto antes de commitear: `regresion.py` anonimiza el nombre del equipo, las IPv4, los
   textos de los mensajes internos y el número de serie, pero conviene buscar nombres de clientes o
   interfaces que hayan quedado dentro de los volcados (por ejemplo, con `grep -i cliente tests/casos/*.json`).
8. Borrar el `.rif` original: el extracto en `tests/casos/` alcanza para las pruebas.

## Formato de una regla

```json
{
  "id": "bt-process-graphing",
  "scope": "backtrace",
  "group": "kind",
  "severity": "medium",
  "match": ["@\\d+: (/\\S*?(graphing))\\s*\\n[^\\n]*--- signal=(\\d+)"],
  "title": "El proceso «graphing» se cayó (señal {3})",
  "detail": "Explicación para quien lee el diagnóstico…",
  "recommend": "Qué hacer, con comandos entre `backticks`.",
  "doc": "https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/graphing.md"
}
```

| Campo | Obligatorio | Significado |
|---|---|---|
| `id` | sí | Identificador único, en kebab-case. Los tests de regresión lo usan. |
| `scope` | sí | Sobre qué texto se aplica (ver tabla siguiente). |
| `severity` | sí | `critical`, `high`, `medium`, `low` o `info`. |
| `match` | sí | Lista de regex: **todas** tienen que coincidir. Los grupos de la primera se usan en los textos. |
| `title`, `detail`, `recommend` | sí | Textos. Placeholders: `{1}`, `{2}`… (grupos de la primera regex), `{0}` (coincidencia entera) y `{count}` (cantidad de coincidencias). Los comandos van entre backticks; el visor los muestra como código. |
| `not` | no | Lista de regex: si **alguna** coincide, la regla no se aplica. |
| `group` | no | Dentro de un mismo objetivo, solo se aplica la primera regla que coincide de cada grupo. Las reglas específicas tienen que ir **antes** que las genéricas. |
| `requires` | no | Lista de ids: la regla solo se aplica si ya se aplicó alguna de ellas (por ejemplo, un factor de configuración que solo importa si hubo cierto crash). El orden de evaluación es crash → backtrace → log → debug → oops → routerboard → export. |
| `min_count` | no | Mínimo de coincidencias de la primera regex. |
| `min_ratio` | no | Fracción mínima de líneas no vacías del texto que tienen que coincidir con la primera regex (para "el log está saturado de…"). |
| `version_lt` | no | `[a, b]`: solo se aplica si la versión del grupo `a` es menor que la del grupo `b`. |
| `icase` | no | `true` para ignorar mayúsculas y minúsculas. |
| `doc` | no | Enlace a la página del manual (con `.md`; el visor lo quita al mostrarlo). |

### Scopes

| Scope | Texto sobre el que se aplica | Dónde aparece el hallazgo |
|---|---|---|
| `crash` | Cada volcado de `oops`, por separado | En la tarjeta del crash |
| `backtrace` | Cada evento de `backtrace` (y el pendiente de `.debug`) | En el historial |
| `log` | La sección `log` entera | Log y registros internos |
| `debug` | La sección `.debug` entera | Log y registros internos |
| `oops` | La sección `oops` entera | Log y registros internos |
| `routerboard` | La sección `routerboard` | Hallazgos generales |
| `export` | La configuración normalizada: cada línea `add`/`set` lleva su ruta adelante (`/ip route add …`) y las líneas cortadas con `\` se unen | Configuración |

### Reglas de estilo

- **Regex compatibles con Python y JavaScript.** Evitar lookbehind, grupos con nombre, `(?i)` en línea
  y clases POSIX. Usar `[^\n]` en lugar de `.` cuando no se quiere cruzar líneas. Los patrones se
  evalúan en modo multilínea (`^` y `$` por línea).
- **Escribir para quien opera la red**, no para quien programa el kernel: qué pasó, qué significa y qué
  hacer. Si algo es una hipótesis, decirlo ("posible factor", severidad `info`).
- **No confundir el watchdog de RouterOS con los detectores de bloqueo del kernel.**
- Verificar los valores por defecto en el manual antes de afirmarlos (por ejemplo, el timeout de RADIUS
  por defecto es 1100 ms).

## Python y JavaScript

`supout.py` y `viewer/engine.js` implementan la misma lógica, para que la CLI y el visor den siempre el
mismo diagnóstico. Todo cambio fuera de `rules.json` (análisis, motivo del supout, hallazgos calculados)
tiene que hacerse **en los dos**. `tests/paridad.py` compara las salidas sobre todos los casos.

## Casos de regresión

`tests/regresion.py` tiene tres comandos:

- `agregar <rif> <nombre>`: guarda un extracto en `tests/casos/<nombre>.json` con el resultado actual
  como esperado. Si el resultado depende de secciones que no se guardan, avisa.
- `correr`: analiza todos los casos y compara con lo esperado (motivo, hallazgos generales, crashes y
  eventos con los ids de las reglas aplicadas).
- `aceptar`: igual que `correr`, pero toma lo obtenido como nuevo esperado. Usarlo solo después de
  revisar que cada diferencia sea intencional.

Nombre sugerido para los casos: `modelo-version-descripcion` (por ejemplo, `rb4011-v6-loader-cascada`).

## Commits

- No commitear nunca un `.rif` ni nada de `muestras/`.
- Correr `build_viewer.py` antes del commit: `supout-viewer.html` y `docs/REGLAS.md` se versionan.
- Anotar en `CHANGELOG.md` las reglas nuevas y los cambios de comportamiento.
