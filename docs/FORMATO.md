# Formato del archivo supout.rif

RouterOS genera el archivo de soporte de dos formas:

- **`supout.rif`**: a pedido, con `/system/sup-output`.
- **`autosupout.rif`**: automáticamente, cuando ocurre una falla de software (crash del kernel, caída de
  un proceso, reporte de crash de WinBox). Antes de escribir uno nuevo, el anterior se renombra a
  `autosupout.old.rif`.

Según el manual, el watchdog de RouterOS (`/system/watchdog`) **no** escribe un autosupout cuando
reinicia el equipo. `auto-send-supout` permite que se envíe por correo.

## Estructura

El archivo es texto plano formado por bloques:

```
--BEGIN ROUTEROS SUPOUT SECTION
<Base64 en varias líneas>
--END ROUTEROS SUPOUT SECTION
--BEGIN ROUTEROS SUPOUT SECTION
...
```

Cada bloque es una sección. Decodificado, contiene:

```
<nombre de la sección> \0 <datos comprimidos con zlib>
```

### Base64 con bits invertidos

El alfabeto es el estándar (`A–Z a–z 0–9 + /`), pero los bits se acumulan en orden **little-endian**:
cada carácter aporta 6 bits que se agregan *por arriba* de los anteriores, y los bytes se extraen por
abajo. Un decodificador Base64 común devuelve basura. Implementación de referencia: `mt_b64decode()` en
`supout.py` y `mtB64decode()` en `viewer/engine.js`.

### Compresión

Los datos de cada sección son un flujo zlib. Algunas secciones vacías o chicas pueden venir sin
comprimir; en ese caso se toman tal cual.

### Archivos incompletos

Un archivo puede quedar cortado si el router se reinició o se quedó sin memoria mientras lo escribía,
o si la copia se interrumpió. Hay dos casos:

1. **Corte en el medio de una sección:** el último bloque no tiene `--END`, o el flujo zlib no termina.
   Se descomprime lo que se pueda (`zlib.decompressobj` en Python y un lector de `DecompressionStream`
   en el navegador) y la sección se marca como truncada.
2. **Corte entre secciones:** el archivo termina con un `--BEGIN` vacío. Todas las secciones son
   válidas, pero faltan las siguientes. Se detecta porque no está `resource`.

## Secciones

El orden y la cantidad cambian según la versión y el modelo (de 60 a 85 secciones). Las más útiles:

| Sección | Contenido | Uso en el diagnóstico |
|---|---|---|
| `oops` | Volcados del kernel de cada panic, separados por `--- N` … `--- rebooted` | Causa de los reinicios por crash del kernel |
| `backtrace` | Crashes de procesos, kernel panics y reportes de WinBox, agrupados por arranque (`---- current vX ----`, `---- reboot vX ----`) | Historial de fallas; evento que generó el autosupout |
| `.debug` | Registro interno de cada proceso, en bloques `@nombre@` | El bloque `@backtrace@` tiene el último crash procesado |
| `log` | Log en memoria (por defecto 1000 líneas) | Reinicios sin apagado ordenado, watchdog, RADIUS, saturación |
| `resource` | `/system resource` y reloj (fecha, hora, `gmt-offset`) | Uptime, versión, memoria, hora del supout |
| `routerboard` | Modelo, número de serie y versiones de RouterBOOT | Firmware desalineado |
| `export` | Configuración completa (`/export`) | Factores de configuración |
| `ppp` | Sesiones PPP activas | Cantidad de sesiones |
| `health` | Temperaturas, tensiones, fuentes | Problemas de hardware |
| `.proc` | Copia de `/proc` (incluye conntrack) | Suele ser la sección más grande |

### Formato de `oops`

Cada crash empieza con `--- N` y una línea `v<versión> <fecha de build> at <fecha del crash>`, y
termina con `--- rebooted`. La hora del crash sale del reloj del equipo al guardar el volcado y **no
siempre es confiable**: en equipos que arrancan sin hora y crashean antes de sincronizar NTP pueden
aparecer varios crashes con la misma hora exacta.

En v7 y en ARM/x86 las líneas tienen el formato del kernel de Linux (`[ 1234.567890] mensaje`), del que
se saca el uptime al momento del crash. En los CCR con CPU Tilera (v6) no hay marca de tiempo y el crash
aparece como `Kernel took bad trap N (motivo) at PC … función`.

### Formato de `backtrace`

```
---- current v7.21.1 2026-01-19 15:09:07 ----
2026.04.15-23:19:03.42@5: /nova/bin/graphing
2026.04.15-23:19:03.42@5: --- signal=11 -----------------------------------
...registros, mapas de memoria, pila, código, backtrace: 0x...
```

- Las horas de los eventos están en **UTC**.
- `current` es el arranque actual; `reboot` son arranques anteriores.
- Los eventos empiezan con la ruta del proceso, `had panic` (kernel panic) o `WinBox`.
- Cuando varios procesos se caen a la vez, sus volcados pueden quedar mezclados línea por línea.

### Formato de `.debug`

Una secuencia de bloques `@proceso@` con el final del registro interno de cada proceso. Dos usos:

- `@backtrace@` es el registro del proceso que guarda los crashes y escribe el autosupout: contiene el
  último crash procesado, que puede todavía no estar en la sección `backtrace`.
- En v6 aparecen mensajes `checkForFreeMemory` / `flusing queue`, de significado no documentado.
