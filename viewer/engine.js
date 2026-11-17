// Motor de análisis del visor: equivalente en JS de supout.py (mismas reglas, rules.json).
// No depende del DOM; expone SupoutEngine.{decodeFile, analyze}.
var SupoutEngine = (function () {
  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var IDX = {};
  for (var i = 0; i < B64.length; i++) IDX[B64[i]] = i;
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

  function mtB64decode(s) {
    s = s.replace(/\s/g, "");
    var out = new Uint8Array(Math.floor(s.length / 4) * 3 + 3), p = 0;
    for (var i = 0; i < s.length; i += 4) {
      var o = 0, n = 0;
      for (var j = 0; j < 4 && i + j < s.length; j++) {
        var c = s[i + j];
        if (c === "=") break;
        o += IDX[c] * Math.pow(2, 6 * j); // evita overflow de bits en 32 bits con signo
        n++;
      }
      var nb = n === 2 ? 1 : n === 3 ? 2 : n === 4 ? 3 : 0;
      for (var k = 0; k < nb; k++) out[p++] = Math.floor(o / Math.pow(2, 8 * k)) & 0xff;
    }
    return out.subarray(0, p);
  }

  // inflate: async (Uint8Array) -> {data, complete}. En el navegador usa DecompressionStream y,
  // si el flujo zlib está cortado, devuelve lo que alcanzó a descomprimir.
  async function browserInflate(bytes) {
    var ds = new DecompressionStream("deflate"), w = ds.writable.getWriter();
    w.write(bytes).catch(function () {});
    w.close().catch(function () {});
    var reader = ds.readable.getReader(), chunks = [], size = 0, complete = true;
    try {
      for (;;) {
        var r = await reader.read();
        if (r.done) break;
        chunks.push(r.value); size += r.value.length;
      }
    } catch (e) { complete = false; }
    if (!complete && !size) throw new Error("no es zlib");
    var out = new Uint8Array(size), p = 0;
    chunks.forEach(function (c) { out.set(c, p); p += c.length; });
    return { data: out, complete: complete };
  }

  var BEGIN = "--BEGIN ROUTEROS SUPOUT SECTION", END = "--END ROUTEROS SUPOUT SECTION";

  async function decodeFile(text, inflate, onProgress) {
    inflate = inflate || browserInflate;
    var blocks = text.split(BEGIN).slice(1), sections = [];
    var dec = new TextDecoder("utf-8");
    for (var i = 0; i < blocks.length; i++) {
      var complete = blocks[i].indexOf(END) >= 0;
      var raw = mtB64decode(blocks[i].split(END)[0]);
      var nul = raw.indexOf(0);
      if (nul < 0) continue;
      var name = String.fromCharCode.apply(null, raw.subarray(0, nul));
      var data = raw.subarray(nul + 1), truncated = !complete;
      try {
        var res = await inflate(data);
        data = res.data; truncated = truncated || (!res.complete && data.length > 0);
      } catch (e) { /* sin comprimir o ilegible: se deja tal cual */ }
      sections.push({ name: name, text: dec.decode(data).replace(/\r\n/g, "\n"), truncated: truncated });
      if (onProgress) onProgress(i + 1, blocks.length, name);
    }
    if (!sections.length) throw new Error("No se encontraron secciones: ¿es un archivo supout.rif?");
    return sections;
  }

  // ------------------------------------------------------------ parsers
  function first(re, text, def) {
    var m = re.exec(text || "");
    return m ? m[1].trim() : (def === undefined ? null : def);
  }
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function fmtUptime(sec) {
    var s = Math.floor(sec), d = Math.floor(s / 86400); s %= 86400;
    var h = Math.floor(s / 3600); s %= 3600;
    var mi = Math.floor(s / 60); s %= 60;
    return (d ? d + "d " : "") + pad(h) + ":" + pad(mi) + ":" + pad(s);
  }

  function parseRosUptime(s) {
    if (!s) return null;
    var units = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 }, re = /(\d+)([wdhms])/g, m, tot = 0, any = false;
    while ((m = re.exec(s))) { tot += parseInt(m[1], 10) * units[m[2]]; any = true; }
    return any ? tot : null;
  }

  function normalizeExport(text) {
    var lines = [], buf = "";
    (text || "").split("\n").forEach(function (line) {
      if (/\\$/.test(line)) { buf += line.slice(0, -1).trim() + " "; return; }
      lines.push(buf ? buf + line.trim() : line); buf = "";
    });
    var out = [], cur = "";
    lines.forEach(function (line) {
      if (line[0] === "/") { cur = line.trim(); out.push(cur); }
      else if (line.trim() && line.trim()[0] !== "#") out.push(cur + " " + line.trim());
    });
    return out.join("\n");
  }

  function parseCrashes(oops) {
    var parts = (oops || "").split(/^--- (\d+)[ \t]*$/m), crashes = [];
    for (var i = 1; i < parts.length; i += 2) {
      var body = parts[i + 1].replace(/^--- rebooted[ \t]*$/mg, "").trim();
      var stamps = [], sm, sre = /^(?:DUMP: )?\[\s*(\d+\.\d+)\]/mg;
      while ((sm = sre.exec(body))) stamps.push(parseFloat(sm[1]));
      var msgs = {};
      body.split("\n").forEach(function (line) {
        var msg = line.replace(/^(?:DUMP: )?(?:\[[^\]]*\](?:\[[^\]]*\])?\s*)?(?:<\d>)?\s*/, "").trim();
        if (msg && msg.indexOf("_stext") !== 0) msgs[msg] = (msgs[msg] || 0) + 1;
      });
      var funcs = [], fm, fre = /\b([A-Za-z_]\w*)\+0x[0-9a-f]+\/0x[0-9a-f]+/g;
      while ((fm = fre.exec(body))) if (fm[1] !== "_stext" && funcs.indexOf(fm[1]) < 0) funcs.push(fm[1]);
      var mods = {}, mm, mre = /\[(\w+)@0x/g;
      while ((mm = mre.exec(body))) mods[mm[1]] = 1;
      var repeated = Object.keys(msgs).map(function (k) { return { msg: k, count: msgs[k] }; })
        .filter(function (x) { return x.count >= 3; })
        .sort(function (a, b) { return b.count - a.count; }).slice(0, 3);
      crashes.push({
        index: parseInt(parts[i], 10),
        version: first(/^v(\S+)/m, body),
        time: first(/^v\S+ .* at (\S+)/m, body),
        uptime: stamps.length ? fmtUptime(stamps[stamps.length - 1]) : null,
        panic: first(/Kernel panic - not syncing: (.*)$/m, body),
        process: first(/(?:stuck for \d+s! \[|Comm: |comm:\s+)([^\]\s,]+)/m, body),
        functions: funcs.slice(0, 6),
        workqueue: first(/Workqueue: \S+ (\S+)/m, body),
        modules: Object.keys(mods).sort(),
        repeated: repeated,
        text: body
      });
    }
    return crashes;
  }

  function parseBacktraces(bt) {
    var events = [], re = /^---- (\w+) v(\S+) (.+?) ----[ \t]*$/mg, heads = [], m;
    bt = bt || "";
    while ((m = re.exec(bt))) heads.push({ m: m, start: m.index, end: re.lastIndex });
    heads.forEach(function (h, i) {
      var body = bt.slice(h.end, i + 1 < heads.length ? heads[i + 1].start : bt.length).trim();
      if (!body) return;
      var starts = [], sm, sre = /^\S+@\d+: (?:\/\S+|WinBox|had panic)[ \t]*$/mg;
      while ((sm = sre.exec(body))) starts.push(sm.index);
      if (!starts.length) starts = [0];
      starts[0] = 0;
      starts.forEach(function (st, k) {
        var text = body.slice(st, k + 1 < starts.length ? starts[k + 1] : body.length).trim();
        events.push({ boot: h.m[1], version: h.m[2], time: first(/^(\S+?)(?:\.\d+)?@/m, text), text: text });
      });
    });
    return events;
  }

  // Varios volcados con la misma hora exacta: son reinicios distintos pero la fecha no es real.
  function sameTimeFindings(crashes) {
    var counts = {}, order = [];
    crashes.forEach(function (c) {
      if (!c.time) return;
      if (!(c.time in counts)) { counts[c.time] = 0; order.push(c.time); }
      counts[c.time]++;
    });
    return order.filter(function (t) { return counts[t] >= 2; }).map(function (t) {
      return { id: "crash-same-time", severity: "medium",
        title: counts[t] + " crashes del kernel con la misma hora exacta (" + t + ")",
        detail: "Son reinicios distintos (cada volcado termina en su propio «rebooted»), pero quedaron con la misma " +
          "marca de tiempo. La hora sale del reloj del equipo, y si no estaba en hora (por ejemplo, antes de " +
          "sincronizar por NTP) la fecha no es real. Contalos como reinicios separados de fecha desconocida.",
        recommend: "Verificar que NTP esté configurado (`/system ntp client`). Para saber cuándo ocurrieron, cruzar con el monitoreo externo (caídas de ping, sesiones BGP o PPP).",
        doc: "https://manual.mikrotik.com/docs/cli-reference/system/ntp/client.md" };
    });
  }

  // Muchos procesos distintos caídos: apunta a una causa común (versión, memoria, almacenamiento).
  function manyProcessesFindings(events) {
    var names = [];
    events.forEach(function (e) {
      var n = first(/@\d+: \/\S*?([^\/\s]+)\s*\n[^\n]*--- signal=/, e.text);
      if (n && names.indexOf(n) < 0) names.push(n);
    });
    if (names.length < 5) return [];
    return [{ id: "many-processes", severity: "medium",
      title: "Se cayeron " + names.length + " procesos distintos (" + names.join(", ") + ")",
      detail: "Cuando fallan muchos procesos distintos, y no siempre el mismo, lo más probable es una causa común y no un bug de cada proceso: errores de la versión de RouterOS corregidos más adelante, falta de memoria o, menos seguido, almacenamiento o RAM con fallas.",
      recommend: "Actualizar a la última versión long-term. Si sigue pasando, verificar el almacenamiento con `/system check-installation` y revisar la memoria libre.",
      doc: "https://manual.mikrotik.com/docs/cli-reference/system/check-installation.md" }];
  }

  var REBOOT_WINDOW = 1800;
  function supoutTrigger(device, crashes, events, logFindings) {
    var up = parseRosUptime(device.uptime), sEp = supoutEpoch(device);
    var latest = function (list) { return list.reduce(function (a, b) { return (b.time || "") > (a.time || "") ? b : a; }); };
    var cur = events.filter(function (e) { return e.boot === "current" && e.findings && e.findings.length; });
    var procs = cur.filter(function (e) { return e.findings[0].id.indexOf("bt-process") === 0; });
    var near = cur.filter(function (e) {
      var ep = eventEpoch(e.time);
      return sEp != null && ep != null && sEp - ep >= 0 && sEp - ep <= TRIGGER_LAG;
    });
    var trig = near.length ? latest(near) : null, lag = trig ? sEp - eventEpoch(trig.time) : null, fromDebug = false;
    if (up == null) {
      trig = cur.filter(function (e) { return e.debug_last; })[0] || null;
      fromDebug = !!trig;
      if (!trig && procs.length) trig = latest(procs);
      if (!trig) return { kind: "unknown", title: "No se pudo determinar qué generó este supout",
        detail: "Falta la sección resource (uptime) y no hay un crash reciente registrado." };
    } else if (up <= REBOOT_WINDOW) {
      var extra = "";
      if (trig && trig.findings[0].id !== "bt-panic")
        extra = " El autosupout en sí lo escribió un evento posterior al arranque, " + lag + " s antes del supout: " +
          trig.findings[0].title + ".";
      if (crashes.length) return { kind: "kernel-crash", title: "Reinicio por un crash del kernel",
        detail: "El supout se generó con " + device.uptime + " de uptime, justo después de arrancar, e incluye el volcado del crash." + extra };
      if (logFindings.some(function (f) { return f.id === "log-unclean"; })) return { kind: "unclean",
        title: "Reinicio sin apagado ordenado y sin crash del kernel registrado",
        detail: "No hay volcado en la sección oops. Suele indicar un corte de energía, un reset por hardware o un cuelgue que no alcanzó a registrarse." + extra };
      if (!extra) return { kind: "boot", title: "Supout generado poco después de un arranque, sin crash registrado",
        detail: "Uptime " + device.uptime + ". Puede ser un reinicio ordenado o un supout generado a mano." };
    } else if (!trig) {
      if (procs.length && sEp != null) {
        var lp = latest(procs);
        return { kind: "manual", title: "El router no se reinició y no se encontró el evento que generó el supout",
          detail: "Llevaba " + device.uptime + " encendido. La última caída de un proceso en este arranque " +
            "(" + lp.findings[0].title + ", " + lp.time + ") fue bastante antes del supout, así que no lo " +
            "explica. Puede haberse generado a mano (/system/sup-output) o por un evento que no quedó registrado." };
      }
      if (procs.length) {
        var last = latest(procs);
        return { kind: "process", title: "El router no se reinició: " + last.findings[0].title,
          detail: "Llevaba " + device.uptime + " encendido. Cuando un proceso de RouterOS se cae, el sistema lo vuelve a " +
            "levantar y guarda un autosupout sin reiniciar el equipo. Última caída: " + last.time + ".", event_time: last.time };
      }
      return { kind: "manual", title: "El router no se reinició y no hay un crash que explique el supout",
        detail: "Llevaba " + device.uptime + " encendido. Probablemente se generó a mano (/system/sup-output)." };
    }

    var f = trig.findings[0], prefix, head, when;
    if (up == null) {
      prefix = "Probablemente: ";
      head = "No se pudo leer el uptime (falta la sección resource), así que no se sabe si el equipo se reinició. ";
      when = fromDebug ? "Según el registro interno (.debug), es el último crash que procesó RouterOS (" + trig.time + ")."
        : "Es la última caída registrada en el arranque actual (" + trig.time + ").";
    } else if (up <= REBOOT_WINDOW) {
      prefix = "";
      head = "Llevaba " + device.uptime + " encendido: el equipo había arrancado hacía poco, sin crash registrado, " +
        "pero el supout no salió del arranque. ";
      when = "Se escribió " + lag + " s después (" + trig.time + ").";
    } else {
      prefix = "El router no se reinició: ";
      head = "Llevaba " + device.uptime + " encendido. ";
      when = "Se escribió " + lag + " s después (" + trig.time + ").";
    }
    if (f.id === "bt-winbox") {
      var wb = first(/winbox version: ?(\S+)/, trig.text) || "";
      return { kind: "winbox", title: prefix + (prefix ? "lo" : "Lo") + " generó un crash de WinBox en una PC",
        detail: head + "El autosupout salió del reporte de un crash de WinBox " + wb + " enviado desde una PC. " + when, event_time: trig.time };
    }
    if (f.id.indexOf("bt-process") === 0) return { kind: "process", title: prefix + f.title,
      detail: head + "Cuando un proceso de RouterOS se cae, el sistema lo vuelve a levantar y guarda un " +
        "autosupout sin reiniciar el equipo. " + when, event_time: trig.time };
    if (f.id === "bt-panic" && up == null) return { kind: "kernel-crash", title: "Probablemente: reinicio por un crash del kernel",
      detail: head + "El último evento que procesó RouterOS fue un kernel panic. " + when };
    return { kind: "manual", title: "No se pudo determinar qué generó este supout", detail: head.trim() };
  }

  // El bloque @backtrace@ de .debug guarda el último crash que procesó RouterOS (el que generó el autosupout).
  // Devuelve [hora, texto] o null. Si todavía no llegó a la sección backtrace, se agrega como evento pendiente.
  function debugBacktrace(debug) {
    var m = /^@backtrace@[ \t]*\n([\s\S]*?)(?=^@[\w.-]+@[ \t]*$|(?![\s\S]))/m.exec(debug || "");
    if (!m || !/backtrace: 0x|had panic|WinBox|--- signal=/.test(m[1])) return null;
    var text = m[1].trim();
    var t = first(/^(\d{4}\.\d\d\.\d\d-\d\d:\d\d:\d\d)/m, text);
    return t ? [t, text] : null;
  }

  function deviceInfo(sec) {
    var res = sec.resource || "", rb = sec.routerboard || "", exp = sec["export"] || "", ppp = sec.ppp;
    var join = function (arr, sep) { var a = arr.filter(Boolean); return a.length ? a.join(sep) : null; };
    return {
      identity: first(/^\/system identity\s*\nset name="?([^"\n]+)/m, exp),
      model: first(/^\s*model: (.+)$/m, rb) || first(/^\s*board-name: (.+)$/m, res),
      serial: first(/^\s*serial-number: (.+)$/m, rb),
      version: first(/^\s*version: (.+)$/m, res),
      firmware: first(/^\s*current-firmware: (.+)$/m, rb),
      uptime: first(/^\s*uptime: (\S+)/m, res),
      date: join([first(/^\s*date: (\S+)/m, res), first(/^\s*time: (\S+)/m, res)], " "),
      timezone: first(/^\s*time-zone-name: (\S+)/m, res),
      gmt_offset: first(/^\s*gmt-offset: ([+-]\d\d:\d\d)/m, res),
      memory: join([first(/^\s*free-memory: (\S+)/m, res), first(/^\s*total-memory: (\S+)/m, res)], " / "),
      cpu: join([first(/^\s*cpu-count: (\S+)/m, res), "x", first(/^\s*cpu-frequency: (\S+)/m, res)], " "),
      ppp_active: ppp ? (ppp.match(/^\s*\d+\s+\S*\s*name=/mg) || []).length : null
    };
  }

  // ------------------------------------------------------------ reglas
  function fill(tpl, count, groups) {
    return (tpl || "").replace(/\{(count|\d+)\}/g, function (_, k) {
      if (k === "count") return String(count);
      var i = parseInt(k, 10);
      return i < groups.length && groups[i] != null ? groups[i] : "";
    });
  }

  function versionKey(v) { return ((v || "").match(/\d+/g) || []).map(Number); }
  function versionLess(a, b) {
    for (var i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] < b[i];
    return a.length < b.length;
  }

  var MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  // Hora UTC (epoch, en segundos) en que se generó el supout, a partir de date/time y gmt-offset de resource.
  function supoutEpoch(device) {
    var d = device.date || "", y, mo, day, hh, mi, ss;
    var m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/.exec(d);
    if (m) { y = +m[1]; mo = +m[2]; day = +m[3]; hh = +m[4]; mi = +m[5]; ss = +m[6]; }
    else {
      m = /^([a-z]{3})\/(\d\d)\/(\d{4}) (\d\d):(\d\d):(\d\d)$/.exec(d.toLowerCase());
      if (!m || MONTHS.indexOf(m[1]) < 0) return null;
      mo = MONTHS.indexOf(m[1]) + 1; day = +m[2]; y = +m[3]; hh = +m[4]; mi = +m[5]; ss = +m[6];
    }
    var off = /^([+-])(\d\d):(\d\d)$/.exec(device.gmt_offset || "");
    if (!off) return null;
    var sign = off[1] === "-" ? -1 : 1;
    return Date.UTC(y, mo - 1, day, hh, mi, ss) / 1000 - sign * (+off[2] * 3600 + +off[3] * 60);
  }
  // '2026.05.29-10:45:58' (UTC, como en backtrace) → epoch.
  function eventEpoch(t) {
    var m = /^(\d{4})\.(\d\d)\.(\d\d)-(\d\d):(\d\d):(\d\d)$/.exec(t || "");
    return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000 : null;
  }
  var TRIGGER_LAG = 300; // el autosupout se escribe segundos después del evento que lo genera

  function applyRule(rule, text, fired) {
    if (rule.requires && !rule.requires.some(function (r) { return fired[r]; })) return null;
    var flags = "m" + (rule.icase ? "i" : ""), m0 = null, count = 0;
    for (var i = 0; i < rule.match.length; i++) {
      var m = new RegExp(rule.match[i], flags).exec(text);
      if (!m) return null;
      if (i === 0) { m0 = m; count = (text.match(new RegExp(rule.match[i], flags + "g")) || []).length; }
    }
    if ((rule.not || []).some(function (p) { return new RegExp(p, flags).test(text); })) return null;
    if (rule.version_lt) {
      var va = versionKey(m0[rule.version_lt[0]]), vb = versionKey(m0[rule.version_lt[1]]);
      if (!versionLess(va, vb)) return null;
    }
    if (count < (rule.min_count || 1)) return null;
    if (rule.min_ratio && count / Math.max(1, text.split("\n").filter(function (l) { return l.trim(); }).length) < rule.min_ratio) return null;
    var groups = Array.prototype.slice.call(m0);
    return {
      id: rule.id, severity: rule.severity,
      title: fill(rule.title, count, groups),
      detail: fill(rule.detail, count, groups),
      recommend: fill(rule.recommend, count, groups),
      doc: rule.doc || null
    };
  }

  function runRules(rules, scope, targets, fired) {
    return targets.map(function (text) {
      var found = [], used = {};
      rules.filter(function (r) { return r.scope === scope; }).forEach(function (rule) {
        if (rule.group && used[rule.group]) return;
        var f = applyRule(rule, text, fired);
        if (f) { found.push(f); fired[f.id] = true; if (rule.group) used[rule.group] = true; }
      });
      return found;
    });
  }

  function analyze(fileName, sections, rules) {
    var sec = {};
    sections.forEach(function (s) { if (!(s.name in sec)) sec[s.name] = s.text; });
    var fired = {};
    var crashes = parseCrashes(sec.oops);
    runRules(rules, "crash", crashes.map(function (c) { return c.text; }), fired)
      .forEach(function (f, i) { crashes[i].findings = f; });
    var bts = parseBacktraces(sec.backtrace);
    var dbt = debugBacktrace(sec[".debug"]);
    if (dbt) {
      var same = bts.filter(function (e) { return e.time === dbt[0]; });
      if (same.length) same[same.length - 1].debug_last = true;
      else bts.push({ boot: "current", version: first(/^\s*version: (\S+)/m, sec.resource || "") || "?",
        time: dbt[0], text: dbt[1], pending: true, debug_last: true });
    }
    runRules(rules, "backtrace", bts.map(function (b) { return b.text; }), fired)
      .forEach(function (f, i) { bts[i].findings = f; });
    var logF = runRules(rules, "log", [sec.log || ""], fired)[0]
      .concat(runRules(rules, "debug", [sec[".debug"] || ""], fired)[0])
      .concat(runRules(rules, "oops", [sec.oops || ""], fired)[0]);
    var device = deviceInfo(sec);
    if (!device.version) { // archivo incompleto: tomar la versión del arranque actual en backtrace
      var cv = bts.filter(function (e) { return e.boot === "current" && !e.pending; })[0];
      device.version = cv ? cv.version : null;
    }
    var general = sections.filter(function (s) { return s.truncated; }).map(function (s) {
      return { id: "file-truncated", severity: "high", title: "Archivo incompleto: se corta en la sección «" + s.name + "»",
        detail: "Faltan las secciones siguientes (log, configuración, etc.). Pasa si el router se reinició o se quedó " +
          "sin memoria mientras generaba el archivo, o si la descarga/copia quedó incompleta. " +
          "Se analizó lo que se pudo recuperar.",
        recommend: "Si el archivo original en el router está completo, volver a descargarlo.", doc: null };
    });
    general = general.concat(runRules(rules, "routerboard", [sec.routerboard || ""], fired)[0]);
    if (sections.length && !sections.some(function (x) { return x.truncated; }) && !("resource" in sec))
      general.push({ id: "file-truncated", severity: "high",
        title: "Archivo incompleto: termina después de la sección «" + sections[sections.length - 1].name + "»",
        detail: "Faltan las secciones siguientes (resource, log, configuración, etc.), así que no hay datos del " +
          "equipo ni uptime. Pasa si el router se reinició o se quedó sin memoria mientras generaba el " +
          "archivo, o si la descarga/copia quedó incompleta. Se analizó lo que se pudo recuperar.",
        recommend: "Si el archivo original en el router está completo, volver a descargarlo.", doc: null });
    general = general.concat(sameTimeFindings(crashes));
    general = general.concat(manyProcessesFindings(bts));
    var cfgF = runRules(rules, "export", [normalizeExport(sec["export"])], fired)[0];
    var bySev = function (a, b) { return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity); };
    return {
      file: fileName,
      device: device,
      trigger: supoutTrigger(device, crashes, bts, logF),
      general_findings: general,
      crashes: crashes,
      backtraces: bts,
      log_findings: logF,
      config_findings: cfgF.sort(bySev),
      critical_log: (sec.log || "").split("\n").filter(function (l) {
        return /,(critical|error)\b/.test(l) && l.indexOf("pppoe") < 0;
      }).slice(0, 50),
      health: (sec.health || "").trim(),
      sections: sections
    };
  }

  return { decodeFile: decodeFile, analyze: analyze, normalizeExport: normalizeExport, SEVERITY_ORDER: SEVERITY_ORDER };
})();
if (typeof module !== "undefined") module.exports = SupoutEngine;
