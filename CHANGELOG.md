# Historial de cambios

## 0.1.0 — 2026-11-17

Primera versión, construida y ajustada sobre 12 supouts reales (CCR2116, CCR1036, CRS317 y RB4011,
RouterOS v6 y v7).

### Decodificación
- Lectura de `supout.rif` / `autosupout.rif`: Base64 de MikroTik (bits little-endian) + zlib.
- Recuperación parcial de archivos cortados en el medio de una sección y detección de archivos cortados
  entre secciones.
- CLI (`supout.py`): informe, JSON, listado, extracción y visualización de secciones.
- Visor autocontenido (`supout-viewer.html`): varios archivos con pestañas, resumen para ticket,
  explorador de secciones con filtro y descarga.

### Motivo del supout
- Distingue reinicio por crash del kernel, reinicio sin apagado ordenado, caída de un proceso sin
  reinicio, crash de WinBox en una PC y generación manual.
- Cruza la hora del supout (pasada a UTC con `gmt-offset`) con los eventos de `backtrace` (UTC) para
  encontrar el evento que lo generó.
- Usa el bloque `@backtrace@` de `.debug` para eventos que todavía no llegaron a `backtrace` y para
  archivos incompletos.

### Reglas (46)
- Crashes del kernel: bloqueo al liberar interfaces PPP, limpieza de conexiones de masquerade, OOM,
  hard/soft lockup, hung task, fallos de memoria, crash del scheduler en Tilera, excepciones de Tilera.
- Procesos: graphing (también por su registro interno), ssh, login, loader, volcados mezclados, WinBox.
- Log: reinicios sin apagado, watchdog de ping, RADIUS, OOM, NTP, saturación por firewall, logins o PPP.
- Kernel previo al crash: tabla de conexiones llena, desborde del route cache.
- Configuración: timeout de RADIUS, sniffer sobre interfaz borrada, referencias a interfaces
  inexistentes, DHCPv6-PD en PPP, BFD en todas las interfaces, traffic-flow, graphing en todas las
  interfaces.
- Hardware: RouterBOOT desactualizado o más nuevo que RouterOS.
- Calculados: crashes con la misma hora exacta, muchos procesos distintos caídos, archivo incompleto.

### Proyecto
- Licencia MIT.

### Pruebas
- 12 casos de regresión con extractos anonimizados (nombre del equipo, IPv4, textos de mensajes internos y
  número de serie).
- Prueba de paridad entre la CLI (Python) y el visor (JavaScript).
