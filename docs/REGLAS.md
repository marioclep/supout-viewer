# Catálogo de reglas

> Generado por `build_viewer.py` a partir de `rules.json`. No editar a mano.

Total: **46 reglas**. Formato de cada regla: ver [CONTRIBUIR.md](CONTRIBUIR.md#formato-de-una-regla).

## Crashes del kernel (cada volcado de la sección `oops`)

Dentro de cada objetivo solo se aplica la primera regla que coincide de cada grupo (`cause`), en el orden de esta tabla.

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `masquerade-conntrack-lockup` | crítico | CPU {1} bloqueada {2}s limpiando conexiones de masquerade ([manual](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/nat)) | grupo `cause` |
| `ppp-netdev-lockup` | crítico | Bloqueo del kernel al liberar una interfaz PPP ({1}) ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `netdev-lockup` | crítico | Bloqueo del kernel al liberar la interfaz {1} ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `oom` | crítico | Sin memoria (OOM) ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `hard-lockup` | crítico | Hard lockup de CPU ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `kernel-memfault` | crítico | Fallo de acceso a memoria en el kernel ({1}) ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `soft-lockup` | alto | CPU {1} bloqueada {2}s (proceso {3}) ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `hung-task` | alto | Tarea del kernel bloqueada más de {1}s ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `kernel-bug` | alto | Error interno del kernel ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `tilera-sched-udivdi3` | crítico | Crash del scheduler del kernel (\_\_udivdi3 en find\_busiest\_group) ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `kernel-bad-trap` | crítico | Excepción del kernel: {2} en {3} ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |
| `panic-generic` | alto | Kernel panic: {1} ([manual](https://manual.mikrotik.com/docs/getting-started/supout-rif)) | grupo `cause` |

## Crashes de procesos y WinBox (cada evento de la sección `backtrace`)

Dentro de cada objetivo solo se aplica la primera regla que coincide de cada grupo (`kind`), en el orden de esta tabla.

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `bt-winbox` | info | Crash de WinBox {1} en una PC (no afecta al router) | grupo `kind` |
| `bt-panic` | info | Marca de kernel panic | grupo `kind` |
| `bt-process-loader` | alto | Se cayó «loader», el proceso que supervisa a los demás (señal {3}) | grupo `kind` |
| `bt-process-graphing` | medio | El proceso «graphing» se cayó (señal {3}) ([manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/graphing)) | grupo `kind` |
| `bt-process-graphing-logtail` | medio | El proceso «graphing» se cayó ([manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/graphing)) | grupo `kind` |
| `bt-process-ssh` | medio | El servidor SSH («ssh») se cayó (señal {3}) ([manual](https://manual.mikrotik.com/docs/cli-reference/ip/service)) | grupo `kind` |
| `bt-process-login` | medio | El proceso «login» se cayó (señal {3}) ([manual](https://manual.mikrotik.com/docs/authentication-authorization-accounting/user)) | grupo `kind` |
| `bt-process-signal` | medio | El proceso «{2}» se cayó (señal {3}) | grupo `kind` |
| `bt-process-garbled` | medio | Varios procesos se cayeron a la vez (volcados mezclados) | grupo `kind` |
| `bt-process` | alto | Crash de un proceso de RouterOS | grupo `kind` |

## Log del equipo (sección `log`, completa)

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `log-unclean` | alto | Reinicio sin apagado ordenado ({count} en el log) |  |
| `log-kernel-failure` | alto | RouterOS registró una falla del kernel en el arranque anterior |  |
| `log-watchdog` | alto | Mensajes del watchdog en el log ({count}) ([manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/watchdog)) |  |
| `log-ping-watchdog` | alto | Reinicio por ping watchdog ({count}) ([manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/watchdog)) |  |
| `log-radius-timeout` | medio | {count} autenticaciones PPP fallaron por timeout de RADIUS ([manual](https://manual.mikrotik.com/docs/cli-reference/radius)) | mín. 5 apariciones |
| `log-oom` | alto | Falta de memoria en el log ({count}) |  |
| `log-health` | alto | Alertas de hardware (temperatura, ventiladores o alimentación): {count} |  |
| `log-ntp-jump` | info | El reloj se corrigió por NTP después del arranque |  |
| `log-firewall-flood` | medio | El log está saturado por el firewall ({count} líneas) ([manual](https://manual.mikrotik.com/docs/cli-reference/system/logging)) | ≥ 50 % de las líneas |
| `log-account-flood` | bajo | El log está ocupado por inicios de sesión ({count} líneas) ([manual](https://manual.mikrotik.com/docs/cli-reference/system/logging)) | ≥ 50 % de las líneas |
| `log-ppp-flood` | bajo | El log está ocupado por conexiones PPP ({count} líneas) ([manual](https://manual.mikrotik.com/docs/cli-reference/system/logging)) | ≥ 60 % de las líneas |

## Registro interno (sección `.debug`, completa)

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `debug-backtrace-loop` | medio | El proceso que guarda los crashes entró en un bucle de errores ({count} señales) | mín. 100 apariciones |
| `debug-memory-pressure` | info | Mensajes internos de control de memoria en .debug ({count}) | mín. 3 apariciones |

## Mensajes del kernel previos a los crashes (sección `oops`, completa)

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `oops-conntrack-full` | medio | La tabla de conexiones se llenó antes de los crashes ({count} avisos) ([manual](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking)) |  |
| `oops-dst-cache-overflow` | medio | Desborde del route cache del kernel ({count} avisos) ([manual](https://manual.mikrotik.com/docs/cli-reference/ip/settings)) |  |

## Hardware y firmware (sección `routerboard`)

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `hw-firmware-outdated` | bajo | RouterBOOT desactualizado: {1} (disponible {2}) ([manual](https://manual.mikrotik.com/docs/cli-reference/system/routerboard/upgrade)) | compara versiones |
| `hw-firmware-newer` | info | RouterBOOT más nuevo que RouterOS: {1} con RouterOS {2} ([manual](https://manual.mikrotik.com/docs/cli-reference/system/routerboard/upgrade)) | compara versiones |

## Configuración (sección `export`, normalizada)

| Regla | Severidad | Título | Condiciones |
|---|---|---|---|
| `cfg-radius-timeout` | medio | Timeout de RADIUS bajo ({1} ms; el valor por defecto es 1100 ms) ([manual](https://manual.mikrotik.com/docs/cli-reference/radius)) |  |
| `cfg-sniffer-stale` | medio | Sniffer configurado sobre una interfaz inexistente ({1}) ([manual](https://manual.mikrotik.com/docs/cli-reference/tool/sniffer)) |  |
| `cfg-stale-iface` | bajo | Referencias a interfaces inexistentes ({count}) |  |
| `cfg-ppp-ipv6pd` | info | Posible factor: las sesiones PPP entregan IPv6 (DHCPv6-PD) ([manual](https://manual.mikrotik.com/docs/cli-reference/ppp/profile)) | requiere `ppp-netdev-lockup` |
| `cfg-bfd-all` | info | Posible factor: BFD habilitado en todas las interfaces ([manual](https://manual.mikrotik.com/docs/cli-reference/routing/bfd/configuration)) | requiere `ppp-netdev-lockup`, `netdev-lockup` |
| `cfg-traffic-flow` | info | Posible factor: traffic-flow activo ([manual](https://manual.mikrotik.com/docs/cli-reference/ip/traffic-flow)) | requiere `ppp-netdev-lockup`, `netdev-lockup` |
| `cfg-graphing-all` | bajo | Graphing está graficando todas las interfaces ([manual](https://manual.mikrotik.com/docs/cli-reference/tool/graphing/interface)) | requiere `bt-process-graphing` |

## Hallazgos calculados en el código

Estos no están en `rules.json` porque necesitan comparar varios eventos entre sí. Están implementados igual en `supout.py` y `viewer/engine.js`.

| Id | Qué detecta |
|---|---|
| `file-truncated` | Archivo cortado en el medio de una sección, o terminado antes de `resource`. |
| `crash-same-time` | Dos o más crashes del kernel con la misma hora exacta: reinicios distintos con fecha no confiable. |
| `many-processes` | Cinco o más procesos distintos caídos: apunta a una causa común (versión, memoria, almacenamiento). |
