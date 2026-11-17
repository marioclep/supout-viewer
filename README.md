# Supout Viewer

Herramienta para leer los archivos de soporte de MikroTik RouterOS (`supout.rif` y `autosupout.rif`) y
explicar **por qué se generaron**: un reinicio por crash del kernel, un corte de energía, la caída de un
proceso, un crash de WinBox en una PC o una generación manual.

Tiene dos formas de uso, con el mismo motor de reglas:

- **Visor web** (`supout-viewer.html`): un único archivo HTML. Se abre en el navegador, se arrastran los
  `.rif` y se procesan localmente; nada sale de la máquina.
- **Línea de comandos** (`supout.py`): Python 3.8 o posterior, sin dependencias externas.

No necesita IA ni conexión a Internet: el diagnóstico es determinista y sale de reglas declarativas
(`rules.json`), armadas a partir de supouts reales y verificadas contra el
[manual oficial de MikroTik](https://manual.mikrotik.com).

> Proyecto independiente, sin relación con MikroTik.

---

## Inicio rápido

### Visor

1. Abrir `supout-viewer.html` en un navegador moderno (Chrome, Firefox, Safari, Edge).
2. Arrastrar uno o más `.rif` a la página. Con varios archivos aparece una pestaña por cada uno.

El visor muestra:

- **Equipo:** identidad, modelo, versión, firmware, uptime, memoria y sesiones PPP. El botón
  *Copiar resumen para ticket* genera un texto listo para pegar.
- **Motivo del supout:** qué lo generó y cuántos segundos después del evento se escribió.
- **Hallazgos generales:** archivo incompleto, firmware, fechas no confiables y otros.
- **Crashes del kernel**, con la cadena de funciones de la traza y la regla que los explica.
- **Historial de fallas:** todos los eventos de la sección `backtrace` y su arranque.
- **Log, registros internos y configuración:** factores que contribuyen.
- **Explorador de secciones**, con filtro de texto o `/regex/` y descarga de cada sección.

### Línea de comandos

```sh
python3 supout.py autosupout.rif                     # informe de diagnóstico
python3 supout.py *.rif --json                       # diagnóstico en JSON (para integrar con otras herramientas)
python3 supout.py autosupout.rif --list              # lista de secciones con su tamaño
python3 supout.py autosupout.rif --show log          # imprime una sección
python3 supout.py autosupout.rif --extract salida    # guarda todas las secciones como .txt
python3 supout.py autosupout.rif --rules otras.json  # usa un archivo de reglas alternativo
python3 supout.py autosupout.rif --no-color          # sin colores ANSI (para redirigir a un archivo)
```

Ejemplo de salida (resumida):

```
═══ autosupout.rif ═══
Equipo:   CORE · CCR1036-8G-2S+ · S/N XXXXXXXXXXX
RouterOS: 6.49.13 (stable) (firmware 6.49.13)
Supout:   oct/24/2026 20:17:06 America/Argentina/Cordoba · uptime 1m16s · 277 sesiones PPP activas

► Motivo del supout: Reinicio por un crash del kernel
  El supout se generó con 1m16s de uptime, justo después de arrancar, e incluye el volcado del crash.

  [MEDIO] 9 crashes del kernel con la misma hora exacta (2024.03.13-19:43:14)

■ Crashes del kernel (10)
  #0  2026.10.24-18:13:27 (hora del kernel)  ·  RouterOS 6.49.13
      funciones __udivdi3 ← find_busiest_group ← load_balance ← rebalance_domains
    [CRÍTICO] Crash del scheduler del kernel (__udivdi3 en find_busiest_group)
  #1  2024.03.13-19:43:14 (hora del kernel)  ·  RouterOS 6.49.13
    [CRÍTICO] CPU 4 bloqueada 22s limpiando conexiones de masquerade
  ...
■ Log y registros internos
  [MEDIO] La tabla de conexiones se llenó antes de los crashes (71 avisos)
  [MEDIO] Desborde del route cache del kernel (1161 avisos)
```

---

## Qué puede diagnosticar

| Situación | Cómo la reconoce |
|---|---|
| Reinicio por crash del kernel | Uptime corto + volcado en `oops`. Distingue soft/hard lockup, OOM, fallos de memoria, bloqueos al liberar interfaces PPP, limpieza de conexiones de masquerade, crashes de CPU Tilera y otros. |
| Reinicio sin apagado ordenado | Uptime corto, sin volcado, y el aviso del log (corte de energía, reset por hardware). |
| Caída de un proceso sin reinicio | Uptime largo + evento en `backtrace` (o en `.debug`) segundos antes del supout: graphing, ssh, login, loader, etc. |
| Crash de WinBox en una PC | El reporte que WinBox le manda al router también genera un autosupout. |
| Supout generado a mano | Ningún evento que lo explique. |
| Archivo incompleto | Corte en el medio de una sección o antes de `resource`; se analiza lo que se pueda recuperar. |

Además señala factores que contribuyen: tabla de conexiones llena, log saturado, RADIUS con timeout bajo,
interfaces borradas que siguen referenciadas, graphing en todas las interfaces, RouterBOOT desalineado y más.
El catálogo completo está en [docs/REGLAS.md](docs/REGLAS.md).

---

## Documentación

| Documento | Contenido |
|---|---|
| [docs/DIAGNOSTICO.md](docs/DIAGNOSTICO.md) | Cómo se decide el motivo del supout, cómo se analiza cada crash y lo aprendido de los casos reales. |
| [docs/FORMATO.md](docs/FORMATO.md) | El formato del archivo `.rif`: codificación, compresión y secciones. |
| [docs/REGLAS.md](docs/REGLAS.md) | Catálogo de reglas (se genera solo desde `rules.json`). |
| [docs/CONTRIBUIR.md](docs/CONTRIBUIR.md) | Cómo agregar reglas, sumar casos de prueba y mantener sincronizados Python y JavaScript. |
| [CHANGELOG.md](CHANGELOG.md) | Historial de cambios. |

---

## Estructura del repositorio

```
supout.py               Decodificador + motor de reglas + CLI (Python, sin dependencias)
rules.json              Reglas de diagnóstico, compartidas por la CLI y el visor
viewer/engine.js        Port a JavaScript de supout.py (decodificación y análisis)
viewer/template.html    Interfaz del visor
build_viewer.py         Genera supout-viewer.html y docs/REGLAS.md
supout-viewer.html      Visor listo para usar (generado; se versiona para poder descargarlo directo)
tests/regresion.py      Casos de regresión: agregar, correr y aceptar
tests/paridad.py        Verifica que Python y JavaScript den el mismo diagnóstico
tests/casos/            Extractos de supouts reales con el resultado esperado
docs/                   Documentación
```

---

## Desarrollo

Después de cualquier cambio en `rules.json`, `supout.py` o `viewer/`:

```sh
python3 build_viewer.py            # regenera supout-viewer.html y docs/REGLAS.md
python3 tests/regresion.py correr  # los casos reales siguen dando lo esperado
python3 tests/paridad.py           # Python y JavaScript coinciden (requiere Node.js o JavaScriptCore de macOS)
```

Los tres tienen que terminar sin errores antes de hacer commit. Detalle en [docs/CONTRIBUIR.md](docs/CONTRIBUIR.md).

---

## Privacidad

Un supout trae **la configuración completa del equipo**: direcciones, usuarios PPP, secretos de RADIUS,
claves de VPN, el log y la tabla de conexiones. Por eso:

- `.gitignore` excluye `*.rif` y la carpeta `muestras/`. **Nunca commitear un `.rif`.**
- Los casos de `tests/casos/` son extractos reducidos: solo `oops`, `backtrace`, `resource`, `package`,
  `routerboard`, el bloque `@backtrace@` de `.debug` y las líneas de reinicio del log. No tienen
  configuración ni log completo, y están **anonimizados**: número de serie enmascarado, nombre del equipo
  reemplazado, IPv4 cambiadas por direcciones de documentación (RFC 5737) y textos de mensajes internos
  borrados. `tests/regresion.py` lo hace solo al guardar cada caso.
- El visor procesa todo en el navegador y no hace ninguna conexión externa, salvo los enlaces al manual
  que el usuario elija abrir.

---

## Requisitos

- **CLI:** Python 3.8 o posterior.
- **Visor:** cualquier navegador con `DecompressionStream` (Chrome 80+, Firefox 113+, Safari 16.4+).
- **Prueba de paridad:** Node.js, o JavaScriptCore en macOS.

## Licencia

[MIT](LICENSE). Se puede usar, modificar y redistribuir libremente, manteniendo el aviso de copyright.

## Créditos

El formato del archivo (Base64 con bits en orden little-endian y secciones comprimidas con zlib) fue
documentado antes por la comunidad, entre otros en el proyecto *mikrotik-tools*. Las interpretaciones de
los crashes y los valores por defecto se verificaron contra el manual oficial de MikroTik.
