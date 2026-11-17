# Cómo funciona el diagnóstico

El análisis tiene tres partes, implementadas igual en `supout.py` (función `analyze_sections`) y
`viewer/engine.js` (función `analyze`):

1. **Extracción**: se decodifican las secciones y se separan los crashes del kernel (`oops`) y los
   eventos de procesos (`backtrace` y el bloque `@backtrace@` de `.debug`).
2. **Reglas**: cada regla de `rules.json` se aplica sobre su objetivo (un crash, un evento, el log, la
   configuración, etc.) y produce un hallazgo con título, explicación, recomendación y enlace al manual.
3. **Motivo del supout**: se decide qué generó el archivo combinando el uptime, la hora del supout y
   los eventos registrados.

## 1. Motivo del supout

Es la pregunta principal: *¿por qué existe este archivo?* La lógica (`supout_trigger`) sigue este orden:

```
¿Hay uptime (sección resource)?
├─ No → usar el último crash que procesó RouterOS (bloque @backtrace@ de .debug)
│       o, si no está, la última caída del arranque actual  →  "Probablemente: …"
├─ Uptime ≤ 30 min (el equipo acababa de arrancar)
│   ├─ hay volcado en oops            → reinicio por crash del kernel
│   ├─ el log dice "without proper shutdown" → reinicio sin apagado ordenado (corte de energía, reset)
│   ├─ hay un evento ≤ 5 min antes    → lo generó ese evento (no el arranque)
│   └─ nada                           → supout poco después de un arranque, sin crash
└─ Uptime largo (no hubo reinicio)
    ├─ hay un evento del arranque actual ≤ 5 min antes del supout
    │   ├─ crash de WinBox            → lo generó un crash de WinBox en una PC
    │   └─ caída de proceso           → el router no se reinició: se cayó «proceso»
    ├─ hay caídas, pero mucho antes   → no se encontró el evento (posiblemente manual)
    └─ nada                           → generado a mano
```

### Cómo se cruzan las horas

- La hora del supout está en `resource` (`date` y `time`) en **hora local**, junto con `gmt-offset`.
  Se pasa a UTC con ese offset, sin depender de una base de zonas horarias.
- Las horas de `backtrace` están en **UTC**.
- En los casos reales, el autosupout se escribe **entre 8 y 16 segundos** después del evento que lo
  genera. La ventana aceptada es de 300 s (`TRIGGER_LAG`).
- La ventana de "recién arrancado" es de 1800 s (`REBOOT_WINDOW`).

### El bloque `@backtrace@` de `.debug`

En todas las muestras completas, este bloque coincide con el evento que generó el autosupout. Dos
situaciones donde resulta clave:

- **El evento todavía no está en `backtrace`**: RouterOS escribió el autosupout antes de actualizar esa
  sección. Se agrega al historial como evento "solo en .debug". Si el bloque no trae el encabezado con el
  nombre del proceso, se intenta reconocerlo por su registro interno (por ejemplo, graphing escribe
  `writeChangesToStore` e `IFACE UPDATE`).
- **El archivo está incompleto** y no hay uptime: el bloque indica el motivo más probable.

## 2. Crashes del kernel

Cada volcado de `oops` se analiza por separado. De cada uno se extrae:

- versión, hora y uptime al momento del crash (si el formato lo trae);
- proceso o tarea activa (`Comm:`, `stuck for Ns! [proceso]`);
- cadena de funciones de la traza y módulos del kernel involucrados;
- mensajes repetidos antes del crash (por ejemplo, `dst cache overflow ×1161`).

Las reglas de grupo `cause` se prueban en orden y gana la primera que coincide: primero las más
específicas (bloqueo al liberar una interfaz PPP, limpieza de conexiones de masquerade) y al final las
genéricas (`soft-lockup`, `kernel-bad-trap`, `panic-generic`).

**Ojo con la terminología:** un *soft lockup* o *hung task* no es el watchdog de RouterOS
(`/system/watchdog`). Es el detector de bloqueos del propio kernel de Linux, que provoca un kernel panic.
El watchdog de RouterOS reinicia sin escribir autosupout.

## 3. Lecciones de los casos reales

Lo que sigue salió de analizar supouts reales y está cubierto por los casos de `tests/casos/`.

| Caso | Lo aprendido |
|---|---|
| CCR2116 v7, PPPoE | Soft lockups en `ppp_generic` con `unregister_netdevice: waiting for pppX … Usage count`: el kernel no puede liberar una interfaz PPP. Factores: RADIUS con timeout bajo (rotación de sesiones), sniffer sobre una interfaz borrada, DHCPv6-PD en el perfil, BFD en todas las interfaces. |
| CCR1036 v6 (dos equipos) | `Kernel took bad trap … __udivdi3` en `find_busiest_group`: bug del scheduler en CPU Tilera, sin relación con la configuración. |
| CCR1036 v6, 277 PPP | Varios reinicios con una CPU trabada en `ipt_MASQUERADE` → `nf_ct_iterate_cleanup` ← `__inet_del_ifa`: al cerrarse una sesión, masquerade recorre toda la tabla de conexiones. Venía con la tabla llena y el route cache desbordado. |
| CCR1036 v6, varios | Muchos crashes del kernel con **la misma hora exacta**: son reinicios distintos, pero la fecha no es real. |
| CCR1036, CCR2116, CRS317 | `graphing` se cae seguido en v6 y v7, sin reiniciar el equipo. Suele estar configurado sobre todas las interfaces (`/tool graphing interface add` sin `interface=`). |
| CCR1036, RB4011 | Un crash de WinBox en una PC genera un autosupout: no es un problema del router. |
| RB4011 v6.45 / v6.46 | El servidor SSH (`ssh`) se cae en varios equipos, mientras atiende una conexión entrante. |
| RB4011 v6.45 | Si se cae `loader`, arrastra a los demás procesos (señal 6) y los volcados quedan mezclados. |
| RB4011 v6.46 | Archivos cortados justo después de `backtrace`; en uno, el proceso que guarda los crashes entró en un bucle de `[SIGNAL …]`. |
| RB4011 v6.45 | Reinicio sin apagado ordenado y, 14 s después de arrancar, caída de `route`: el autosupout lo escribe la caída, no el corte. |
| Varios | El log en memoria (1000 líneas) suele estar lleno de conexiones PPP, logins o reglas de firewall, y se pierde lo que pasó antes del problema. |
| Varios | RouterBOOT puede quedar más nuevo que RouterOS después de bajar de v7 a v6. |

## Límites

- Las reglas reconocen patrones vistos en casos reales. Un crash desconocido cae en las reglas genéricas
  (`panic-generic`, `bt-process`), que muestran los datos crudos pero no explican la causa.
- Los factores de configuración son **hipótesis** (severidad `info`), no causas confirmadas.
- La hora de los crashes del kernel depende del reloj del equipo y puede ser falsa.
- Faltan casos de equipos ARM chicos (hAP, hEX), CHR y x86, y reinicios reales en v7.
