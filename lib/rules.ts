import { classifyCategory, getCategory } from "./categories.ts";
import type {
  AnalysisResult,
  ColumnMap,
  Finding,
  PriorityTier,
  RemediationAction,
  Severity,
  VulnGroup,
} from "./types.ts";

type Row = Record<string, unknown>;

/* ---------------------------------------------------------------- columnas */

const norm = (s: string) =>
  s
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

// Alias por campo, en orden de preferencia (coincidencia exacta primero, luego "contiene").
const ALIASES: Record<keyof ColumnMap, string[]> = {
  title: ["name", "title", "vulnerability", "vulnerabilidad", "plugin name", "nombre", "finding", "hallazgo", "issue", "vulnerability name", "nvt name", "titulo"],
  severity: ["severity", "severidad", "risk", "riesgo", "risk factor", "criticidad", "threat", "nivel", "rating"],
  cvss: ["cvss v3 base score", "cvss3 base score", "cvss v3", "cvss3", "cvss base score", "cvss score", "cvss", "cvss v4 base score", "base score", "score", "puntaje"],
  cve: ["cve", "cves", "cve id", "cve ids", "cve list"],
  cwe: ["cwe", "cwe id", "cwes"],
  host: ["host", "hostname", "ip", "ip address", "asset", "activo", "dns name", "target", "servidor", "equipo", "asset name", "fqdn", "url"],
  port: ["port", "puerto", "port protocol", "service"],
  description: ["description", "descripcion", "synopsis", "summary", "details", "detalle", "resumen"],
  solution: ["solution", "solucion", "remediation", "remediacion", "fix", "recommendation", "recomendacion", "mitigation", "mitigacion"],
  exploit: ["exploit available", "exploitable", "exploit", "exploit ease", "cisa kev", "kev", "explotable", "known exploited"],
  assetCriticality: ["asset criticality", "criticidad activo", "criticidad del activo", "entorno", "environment", "business criticality", "ambiente"],
};

export function detectColumns(headers: string[]): ColumnMap {
  const map: ColumnMap = {};
  const used = new Set<string>();
  const normHeaders = headers.map((h) => ({ raw: h, n: norm(h) }));
  // assetCriticality antes que severity para que "criticidad activo" no se use como severidad
  const order: (keyof ColumnMap)[] = ["assetCriticality", "cvss", "title", "severity", "cve", "cwe", "host", "port", "description", "solution", "exploit"];
  for (const field of order) {
    const aliases = ALIASES[field];
    let found = normHeaders.find((h) => !used.has(h.raw) && aliases.includes(h.n));
    if (!found)
      found = normHeaders.find(
        (h) => !used.has(h.raw) && aliases.some((a) => a.length > 3 && h.n.includes(a)),
      );
    if (found) {
      map[field] = found.raw;
      used.add(found.raw);
    }
  }
  return map;
}

/* ------------------------------------------------------------- normalizar */

const str = (v: unknown) => (v === null || v === undefined ? "" : String(v).trim());

function parseCvss(v: unknown): number | null {
  const s = str(v).replace(",", ".");
  const m = s.match(/\d+(\.\d+)?/);
  if (!m) return null;
  const n = parseFloat(m[0]);
  return n >= 0 && n <= 10 ? n : null;
}

export function severityFromCvss(cvss: number): Severity {
  if (cvss >= 9) return "Crítica";
  if (cvss >= 7) return "Alta";
  if (cvss >= 4) return "Media";
  if (cvss > 0) return "Baja";
  return "Informativa";
}

function parseSeverity(v: unknown, numericScale5: boolean): Severity | null {
  const s = norm(str(v));
  if (!s) return null;
  if (/^(critical|critica|critico|urgent|urgente|muy alta|p1)/.test(s)) return "Crítica";
  if (/^(high|alta|alto|serious|important|importante|p2)/.test(s)) return "Alta";
  if (/^(medium|media|medio|moderate|moderada|p3)/.test(s)) return "Media";
  if (/^(low|baja|bajo|minimal|minor|p4)/.test(s)) return "Baja";
  if (/^(info|informational|informativa|none|ninguna|log)/.test(s)) return "Informativa";
  const n = parseFloat(s);
  if (!isNaN(n)) {
    // Escala 1-5 (Qualys) o 0-4 (Nessus)
    if (numericScale5) return (["Informativa", "Informativa", "Baja", "Media", "Alta", "Crítica"] as Severity[])[Math.round(n)] ?? null;
    return (["Informativa", "Baja", "Media", "Alta", "Crítica"] as Severity[])[Math.round(n)] ?? null;
  }
  return null;
}

const truthy = (v: unknown) => /^(true|yes|si|sí|y|1|x|available|disponible|easy|exploits? are available|.*metasploit.*|.*kev.*)$/i.test(str(v));

const isCriticalAsset = (v: unknown) =>
  /(prod|production|produccion|critical|critica|critico|alta|high|tier ?1|pci|dmz|internet|externo|publico)/i.test(norm(str(v)));

const splitList = (v: unknown, re: RegExp) => Array.from(new Set(str(v).match(re) ?? [])).map((x) => x.toUpperCase());

/* ---------------------------------------------------------------- scoring */

const SEV_BASE: Record<Severity, number> = { Crítica: 92, Alta: 75, Media: 50, Baja: 22, Informativa: 0 };

export function tierFromScore(score: number): PriorityTier {
  if (score >= 85) return "P1";
  if (score >= 65) return "P2";
  if (score >= 40) return "P3";
  return "P4";
}

export const TIER_INFO: Record<PriorityTier, { label: string; plazo: string }> = {
  P1: { label: "Inmediata", plazo: "Hasta 7 días" },
  P2: { label: "Alta", plazo: "Hasta 30 días" },
  P3: { label: "Media", plazo: "Hasta 90 días" },
  P4: { label: "Baja", plazo: "Planificar o aceptar riesgo" },
};

/**
 * Puntaje de prioridad 0-100:
 *  base por CVSS (x10) o severidad + exploit público (+10) + activo crítico (+5)
 *  + naturaleza de la categoría (RCE, inyección, credenciales...) + alcance (hosts afectados, hasta +6).
 *  Por encima de 80 los puntos valen la mitad, para mantener el orden entre los casos graves.
 *  Las informativas siempre quedan en 0.
 */
function scoreOf(sev: Severity, cvss: number | null, exploit: boolean, critical: boolean, bonus: number, hosts = 1) {
  if (sev === "Informativa") return 0;
  const base = cvss !== null ? Math.max(cvss * 10, SEV_BASE[sev] - 5) : SEV_BASE[sev];
  const reach = hosts > 1 ? Math.min(6, Math.log2(hosts) * 2) : 0;
  const raw = base + (exploit ? 10 : 0) + (critical ? 5 : 0) + bonus * (base / 100) + reach;
  // Compresión suave por encima de 80 para que los casos graves no se aplanen todos en 100
  const soft = raw <= 80 ? raw : 80 + (raw - 80) * 0.5;
  return Math.min(100, Math.round(soft));
}

/* --------------------------------------------------------------- análisis */

export function analyze(rows: Row[], fileName: string): AnalysisResult {
  const warnings: string[] = [];
  const headers = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
  const cols = detectColumns(headers);

  if (!cols.title) warnings.push("No se encontró una columna de nombre/título de vulnerabilidad: se usará la descripción o el CVE.");
  if (!cols.severity && !cols.cvss) warnings.push("No se encontró severidad ni CVSS: la criticidad se estimará por categoría.");

  const sevValues = cols.severity ? rows.map((r) => parseFloat(str(r[cols.severity!]))).filter((n) => !isNaN(n)) : [];
  const scale5 = sevValues.some((n) => n === 5);

  const findings: Finding[] = [];
  rows.forEach((r, i) => {
    const get = (k: keyof ColumnMap) => (cols[k] ? r[cols[k]!] : undefined);
    const description = str(get("description"));
    const cve = splitList(get("cve"), /CVE-\d{4}-\d{4,}/gi);
    const title = str(get("title")) || description.slice(0, 90) || cve[0] || "";
    if (!title) return; // fila vacía

    const cwe = splitList(get("cwe"), /(CWE-)?\d{1,4}/gi).map((c) => (c.startsWith("CWE") ? c : `CWE-${c}`));
    const cvss = parseCvss(get("cvss"));
    const cat = classifyCategory(title, description, cwe);
    const textSev = parseSeverity(get("severity"), scale5);
    const cvssSev = cvss !== null && cvss > 0 ? severityFromCvss(cvss) : null;
    // Se toma la mayor entre la severidad del escáner y la que surge del CVSS
    let severity: Severity =
      textSev && cvssSev ? (SEV_BASE[textSev] >= SEV_BASE[cvssSev] ? textSev : cvssSev) : (textSev ?? cvssSev ?? (cat.bonus >= 8 ? "Alta" : "Media"));
    if (textSev === "Informativa" && !cvssSev) severity = "Informativa";

    const exploit = truthy(get("exploit")) || /exploit (is )?available|metasploit|actively exploited|kev/i.test(description);
    const critical = isCriticalAsset(get("assetCriticality"));
    const score = scoreOf(severity, cvss, exploit, critical, cat.bonus);

    findings.push({
      id: i + 1,
      title,
      severity,
      cvss,
      cve,
      cwe,
      host: str(get("host")) || "(sin host)",
      port: str(get("port")),
      description,
      solution: str(get("solution")),
      exploitAvailable: exploit,
      assetCritical: critical,
      category: cat.name,
      score,
      tier: tierFromScore(score),
    });
  });

  if (rows.length && !findings.length) warnings.push("No se pudo interpretar ninguna fila. Revisá que la primera fila tenga los encabezados.");

  /* -------- agrupar por vulnerabilidad -------- */
  const gmap = new Map<string, VulnGroup>();
  for (const f of findings) {
    const key = norm(f.title);
    let g = gmap.get(key);
    if (!g) {
      const cat = getCategory(f.category);
      g = {
        key,
        title: f.title,
        severity: f.severity,
        cvss: f.cvss,
        cve: [],
        cwe: [],
        category: f.category,
        hosts: [],
        findings: 0,
        exploitAvailable: false,
        score: 0,
        tier: "P4",
        description: f.description,
        solution: f.solution,
        impact: cat.impact,
      };
      gmap.set(key, g);
    }
    g.findings++;
    if (!g.hosts.includes(f.host)) g.hosts.push(f.host);
    g.cve = Array.from(new Set([...g.cve, ...f.cve]));
    g.cwe = Array.from(new Set([...g.cwe, ...f.cwe]));
    g.exploitAvailable ||= f.exploitAvailable;
    if ((f.cvss ?? -1) > (g.cvss ?? -1)) g.cvss = f.cvss;
    if (SEV_BASE[f.severity] > SEV_BASE[g.severity]) g.severity = f.severity;
    if (!g.solution && f.solution) g.solution = f.solution;
    g.score = Math.max(g.score, f.score);
  }
  // Recalcular el puntaje del grupo considerando el alcance (cantidad de hosts)
  for (const g of gmap.values()) {
    const anyCritical = findings.some((f) => norm(f.title) === g.key && f.assetCritical);
    g.score = scoreOf(g.severity, g.cvss, g.exploitAvailable, anyCritical, getCategory(g.category).bonus, g.hosts.length);
    g.tier = tierFromScore(g.score);
  }
  const groups = Array.from(gmap.values()).sort((a, b) => b.score - a.score || b.hosts.length - a.hosts.length);

  /* -------- plan de remediación: agrupar por acción común -------- */
  const riskOf = (g: VulnGroup) => g.score * g.findings;
  const totalRisk = groups.reduce((s, g) => s + riskOf(g), 0);
  const amap = new Map<string, RemediationAction>();
  const actionHosts = new Map<string, Set<string>>();
  for (const g of groups) {
    if (g.severity === "Informativa") continue;
    const { key, action } = actionFor(g);
    let a = amap.get(key);
    if (!a) {
      a = {
        key,
        action,
        category: g.category,
        vulnCount: 0,
        findings: 0,
        hosts: 0,
        maxScore: 0,
        tier: "P4",
        riskReduction: 0,
        solves: getCategory(g.category).solves,
        vulnTitles: [],
      };
      amap.set(key, a);
      actionHosts.set(key, new Set());
    }
    a.vulnCount++;
    a.findings += g.findings;
    a.maxScore = Math.max(a.maxScore, g.score);
    a.riskReduction += totalRisk ? (riskOf(g) / totalRisk) * 100 : 0;
    a.vulnTitles.push(g.title);
    g.hosts.forEach((h) => actionHosts.get(key)!.add(h));
  }
  const actions = Array.from(amap.values())
    .map((a) => ({
      ...a,
      hosts: actionHosts.get(a.key)!.size,
      tier: tierFromScore(a.maxScore),
      riskReduction: Math.round(a.riskReduction * 10) / 10,
    }))
    // Primero lo más urgente; dentro de cada prioridad, lo que más riesgo elimina
    .sort((a, b) => a.tier.localeCompare(b.tier) || b.riskReduction - a.riskReduction);

  return { fileName, columns: cols, findings, groups, actions, totalRisk, warnings };
}

/** Determina la acción de remediación que resuelve el grupo, para agrupar vulnerabilidades con la misma solución. */
function actionFor(g: VulnGroup): { key: string; action: string } {
  const t = `${g.title} ${g.solution}`;
  const isPatch = g.category === "Software desactualizado / sin soporte" || /upgrade|update|actualiz|apply (the )?(security )?patch|parche|hotfix/i.test(g.solution);

  if (/\b(microsoft|windows)\b|\bms\d{2}-\d{3}\b|\bkb\d{6,}\b/i.test(t) && isPatch)
    return { key: "upd:windows", action: "Aplicar las actualizaciones de seguridad de Microsoft Windows" };
  if (/linux kernel|update the kernel|kernel/i.test(t) && isPatch)
    return { key: "upd:kernel", action: "Actualizar el kernel de Linux" };
  if (isPatch && g.category !== "Criptografía y TLS/SSL" && g.category !== "Configuración insegura") {
    const fromSol = g.solution.match(/(?:upgrade|update)\s+(?:to\s+)?(?:the\s+)?(?:a\s+)?(?:version\s+of\s+)?([A-Za-z][\w.+\-/ ]*?)\s+(?:to\s+)?(?:version|v?\d|or later|that is)/i);
    const fromTitle = g.title.match(/^([A-Za-z][\w .+\-/]*?)\s*(?:<|<=|prior to|before|unsupported|\d+\.\d+)/i);
    const name = (fromSol?.[1] || fromTitle?.[1] || g.title.replace(/\(.*?\)/g, "")).trim();
    return { key: `upd:${norm(name)}`, action: `Actualizar ${name} a una versión soportada y parcheada` };
  }
  switch (g.category) {
    case "Criptografía y TLS/SSL":
      if (/certificate|certificado/i.test(t)) return { key: "tls:cert", action: "Renovar los certificados y reemplazarlos por unos emitidos por una CA confiable" };
      return { key: "tls:config", action: "Endurecer la configuración TLS (deshabilitar SSL y TLS 1.0/1.1 y los cifrados débiles)" };
    case "Autenticación y credenciales":
      return { key: "auth", action: "Cambiar credenciales por defecto o débiles y exigir autenticación fuerte (MFA)" };
    case "Inyección (SQL / comandos)":
      return { key: "code:inj", action: "Corregir el código: consultas parametrizadas y validación de entradas" };
    case "Cross-Site Scripting (XSS)":
      return { key: "code:xss", action: "Codificar las salidas de la aplicación y aplicar Content-Security-Policy" };
    case "Exposición de información":
      return { key: "info", action: "Ocultar versiones y banners, y filtrar respuestas que exponen información" };
    case "Configuración insegura":
      if (/header|cabecera|hsts|clickjack|x-frame|content-security|cookie/i.test(t)) return { key: "cfg:headers", action: "Configurar las cabeceras de seguridad HTTP" };
      if (/smb/i.test(t)) return { key: "cfg:smb", action: "Exigir firma SMB y deshabilitar SMBv1" };
      if (/telnet|\bftp\b|cleartext|rsh|rlogin/i.test(t)) return { key: "cfg:services", action: "Deshabilitar servicios inseguros (Telnet, FTP) y usar alternativas cifradas" };
      if (/trace|track|directory listing|directory index|default page|debug/i.test(t)) return { key: "cfg:web", action: "Aplicar hardening al servidor web (métodos HTTP, listado de directorios, páginas por defecto)" };
      return { key: `cfg:${norm(g.title)}`, action: `Corregir configuración: ${g.title}` };
  }
  if (g.solution) {
    const s = g.solution.split(/(?<=\.)\s/)[0].slice(0, 140);
    return { key: `sol:${norm(s)}`, action: s };
  }
  return { key: `vuln:${g.key}`, action: `Remediar: ${g.title}` };
}
