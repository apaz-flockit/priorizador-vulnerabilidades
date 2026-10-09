"use client";

import { Fragment, useMemo, useState } from "react";
import { CategoryChart, SEV_VAR, SeverityChart } from "./Charts";
import { TIER_INFO } from "@/lib/rules.ts";
import type { AiResult, AnalysisResult, PriorityTier, Severity, VulnGroup } from "@/lib/types.ts";
import { SEVERITIES } from "@/lib/types.ts";

interface Props {
  result: AnalysisResult;
  ai: AiResult | null;
  setAi: (a: AiResult | null) => void;
  config: { ai: boolean; requiresAccessCode: boolean };
  onReset: () => void;
}

const FIELD_LABELS: Record<string, string> = {
  title: "Nombre",
  severity: "Severidad",
  cvss: "CVSS",
  cve: "CVE",
  cwe: "CWE",
  host: "Host",
  port: "Puerto",
  description: "Descripción",
  solution: "Solución",
  exploit: "Exploit",
  assetCriticality: "Criticidad del activo",
};

export function SevBadge({ s }: { s: Severity }) {
  return (
    <span className="badge">
      <span className="dot" style={{ background: SEV_VAR[s] }} />
      {s}
    </span>
  );
}

export default function Dashboard({ result, ai, setAi, config, onReset }: Props) {
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);

  const hosts = useMemo(() => new Set(result.findings.map((f) => f.host)).size, [result]);
  const aiMap = useMemo(() => new Map((ai?.vulnerabilidades ?? []).map((v) => [v.key, v])), [ai]);
  const tierCount = (t: PriorityTier) => result.groups.filter((g) => g.tier === t).length;
  const critHigh = result.findings.filter((f) => f.severity === "Crítica" || f.severity === "Alta").length;
  const withExploit = result.groups.filter((g) => g.exploitAvailable && g.severity !== "Informativa").length;

  async function runAi() {
    setAiError(null);
    let code = "";
    if (config.requiresAccessCode) {
      code = window.prompt("Ingresá el código de acceso para el análisis con IA") ?? "";
      if (!code) return;
    }
    setAiLoading(true);
    try {
      const top = result.groups.filter((g) => g.severity !== "Informativa").slice(0, 30);
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(code ? { "x-access-code": code } : {}) },
        body: JSON.stringify({
          vulns: top.map((g) => ({
            key: g.key,
            title: g.title,
            category: g.category,
            severity: g.severity,
            cvss: g.cvss,
            cve: g.cve,
            hosts: g.hosts.length,
            exploitAvailable: g.exploitAvailable,
            tier: g.tier,
            description: g.description,
            solution: g.solution,
          })),
          stats: {
            hallazgos: result.findings.length,
            vulnerabilidadesUnicas: result.groups.length,
            hosts,
            porSeveridad: Object.fromEntries(SEVERITIES.map((s) => [s, result.findings.filter((f) => f.severity === s).length])),
            accionesPrincipales: result.actions.slice(0, 8).map((a) => `${a.tier}: ${a.action} (${a.riskReduction}% del riesgo)`),
          },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? `Error ${res.status}`);
      setAi(data as AiResult);
    } catch (e) {
      setAiError((e as Error).message);
    } finally {
      setAiLoading(false);
    }
  }

  async function pdf() {
    setPdfLoading(true);
    try {
      const { downloadPdf } = await import("@/lib/pdf.ts");
      await downloadPdf(result, ai);
    } finally {
      setPdfLoading(false);
    }
  }

  return (
    <>
      <header className="header">
        <div>
          <h1>Reporte de priorización</h1>
          <p>
            {result.fileName} · {result.findings.length} hallazgos analizados
          </p>
        </div>
        <div className="actions">
          <button className="btn" onClick={onReset}>
            Cargar otro archivo
          </button>
          {config.ai && (
            <button className="btn" onClick={runAi} disabled={aiLoading}>
              {aiLoading && <span className="spinner" />}
              {aiLoading ? "Analizando con IA…" : ai ? "Volver a analizar con IA" : "Analizar impacto con IA"}
            </button>
          )}
          <button className="btn btn-primary" onClick={pdf} disabled={pdfLoading}>
            {pdfLoading && <span className="spinner" />}
            Descargar PDF
          </button>
        </div>
      </header>

      {result.warnings.map((w) => (
        <div key={w} className="alert alert-warn">
          {w}
        </div>
      ))}
      {aiError && <div className="alert alert-error">No se pudo completar el análisis con IA: {aiError}</div>}
      {!config.ai && (
        <div className="alert small muted">
          Análisis con IA no configurado: definí <code>ANTHROPIC_API_KEY</code> en el servidor para obtener impacto de negocio y resumen ejecutivo.
        </div>
      )}

      <section className="kpis">
        <Kpi v={result.findings.length} l="Hallazgos" />
        <Kpi v={result.groups.length} l="Vulnerabilidades únicas" />
        <Kpi v={hosts} l="Hosts afectados" />
        <Kpi v={critHigh} l="Hallazgos críticos o altos" />
        <Kpi v={tierCount("P1")} l="Vulnerabilidades P1 (≤ 7 días)" />
        <Kpi v={withExploit} l="Con exploit público" />
      </section>

      {ai && (
        <section className="card ai-box" style={{ marginBottom: 16 }}>
          <h2>
            Resumen ejecutivo <span className="ai-label">IA</span>
          </h2>
          <p style={{ margin: "6px 0 0" }}>{ai.resumenEjecutivo}</p>
          {ai.riesgosPrincipales?.length > 0 && (
            <>
              <h2 style={{ marginTop: 14 }}>Qué puede pasar si no se remedia</h2>
              <ul>
                {ai.riesgosPrincipales.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}

      <section className="grid-2">
        <div className="card">
          <h2>Hallazgos por criticidad</h2>
          <p className="sub">Cantidad de hallazgos (vulnerabilidad × host) en cada nivel.</p>
          <SeverityChart result={result} />
        </div>
        <div className="card">
          <h2>Hallazgos por tipo de vulnerabilidad</h2>
          <p className="sub">Sin contar los informativos.</p>
          <CategoryChart result={result} />
        </div>
      </section>

      <div className="stack">
        <RemediationPlan result={result} />
        <VulnTable groups={result.groups} aiMap={aiMap} />
        <details className="card small">
          <summary style={{ cursor: "pointer", fontWeight: 600 }}>Columnas detectadas y criterio de priorización</summary>
          <ul className="muted">
            {Object.entries(result.columns).map(([k, v]) => (
              <li key={k}>
                {FIELD_LABELS[k] ?? k}: <b>{v}</b>
              </li>
            ))}
          </ul>
          <p className="muted">
            Puntaje 0-100 = CVSS × 10 (o severidad del escáner) + exploit público (+10) + activo crítico/producción (+5) + tipo de vulnerabilidad
            (RCE, inyección, credenciales suman más) + alcance (cantidad de hosts, hasta +6). Por encima de 80 los puntos se comprimen para
            mantener el orden. P1 ≥ 85 (hasta 7 días), P2 ≥ 65 (30 días), P3 ≥ 40 (90 días), P4 resto.
          </p>
        </details>
      </div>
    </>
  );
}

function Kpi({ v, l }: { v: number; l: string }) {
  return (
    <div className="kpi">
      <div className="v">{v}</div>
      <div className="l">{l}</div>
    </div>
  );
}

function Tier({ t }: { t: PriorityTier }) {
  return (
    <span className={`tier tier-${t}`} title={`${TIER_INFO[t].label} · ${TIER_INFO[t].plazo}`}>
      {t}
    </span>
  );
}

function RemediationPlan({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState<string | null>(null);
  const maxRed = Math.max(...result.actions.map((a) => a.riskReduction), 1);
  return (
    <section className="card">
      <h2>Plan de remediación</h2>
      <p className="sub">Acciones que resuelven varias vulnerabilidades a la vez, ordenadas por urgencia y por el riesgo que eliminan.</p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Prioridad</th>
              <th>Acción</th>
              <th>Vulns</th>
              <th>Hosts</th>
              <th>Riesgo que elimina</th>
              <th>Plazo</th>
            </tr>
          </thead>
          <tbody>
            {result.actions.map((a) => (
              <Fragment key={a.key}>
                <tr className="row" onClick={() => setOpen(open === a.key ? null : a.key)}>
                  <td>
                    <Tier t={a.tier} />
                  </td>
                  <td>
                    <b>{a.action}</b>
                    <div className="muted small">{a.category}</div>
                  </td>
                  <td className="num">{a.vulnCount}</td>
                  <td className="num">{a.hosts}</td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div className="bar-track" style={{ flex: 1 }}>
                        <div className="bar-fill" style={{ width: `${(a.riskReduction / maxRed) * 100}%` }} />
                      </div>
                      <span className="small" style={{ fontVariantNumeric: "tabular-nums", minWidth: 42, textAlign: "right" }}>
                        {a.riskReduction}%
                      </span>
                    </div>
                  </td>
                  <td className="small muted">{TIER_INFO[a.tier].plazo}</td>
                </tr>
                {open === a.key && (
                  <tr className="detail">
                    <td colSpan={6}>
                      <div className="detail-grid">
                        <div>
                          <h4>Problemas que soluciona</h4>
                          <ul style={{ margin: 0, paddingLeft: 18 }}>
                            {a.solves.map((s) => (
                              <li key={s}>{s}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4>Vulnerabilidades que resuelve</h4>
                          <ul style={{ margin: 0, paddingLeft: 18 }}>
                            {a.vulnTitles.map((s) => (
                              <li key={s}>{s}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

type SortKey = "score" | "title" | "cvss" | "hosts";

function VulnTable({ groups, aiMap }: { groups: VulnGroup[]; aiMap: Map<string, { impacto: string; recomendacion: string }> }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [tier, setTier] = useState("");
  const [hideInfo, setHideInfo] = useState(true);
  const [sort, setSort] = useState<{ k: SortKey; dir: 1 | -1 }>({ k: "score", dir: -1 });
  const [open, setOpen] = useState<string | null>(null);

  const cats = useMemo(() => Array.from(new Set(groups.map((g) => g.category))).sort(), [groups]);
  const rows = useMemo(() => {
    const s = q.toLowerCase();
    const val = (g: VulnGroup) => (sort.k === "hosts" ? g.hosts.length : sort.k === "cvss" ? (g.cvss ?? -1) : sort.k === "title" ? g.title : g.score);
    return groups
      .filter(
        (g) =>
          (!hideInfo || g.severity !== "Informativa") &&
          (!sev || g.severity === sev) &&
          (!cat || g.category === cat) &&
          (!tier || g.tier === tier) &&
          (!s || `${g.title} ${g.cve.join(" ")} ${g.hosts.join(" ")}`.toLowerCase().includes(s)),
      )
      .sort((a, b) => {
        const va = val(a), vb = val(b);
        return (va < vb ? -1 : va > vb ? 1 : 0) * sort.dir;
      });
  }, [groups, q, sev, cat, tier, hideInfo, sort]);

  const th = (k: SortKey, label: string) => (
    <th onClick={() => setSort((p) => ({ k, dir: p.k === k ? ((-p.dir) as 1 | -1) : k === "title" ? 1 : -1 }))}>
      {label} {sort.k === k ? (sort.dir === -1 ? "↓" : "↑") : ""}
    </th>
  );

  return (
    <section className="card">
      <h2>Vulnerabilidades priorizadas</h2>
      <p className="sub">Hacé clic en una fila para ver el impacto, la solución y los hosts afectados.</p>
      <div className="filters">
        <input placeholder="Buscar por nombre, CVE o host…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={tier} onChange={(e) => setTier(e.target.value)} aria-label="Prioridad">
          <option value="">Todas las prioridades</option>
          {(["P1", "P2", "P3", "P4"] as PriorityTier[]).map((t) => (
            <option key={t} value={t}>
              {t} · {TIER_INFO[t].label}
            </option>
          ))}
        </select>
        <select value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Criticidad">
          <option value="">Todas las criticidades</option>
          {SEVERITIES.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Tipo">
          <option value="">Todos los tipos</option>
          {cats.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <label className="small muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <input type="checkbox" checked={hideInfo} onChange={(e) => setHideInfo(e.target.checked)} /> Ocultar informativas
        </label>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {th("score", "Prioridad")}
              {th("title", "Vulnerabilidad")}
              <th>Criticidad</th>
              {th("cvss", "CVSS")}
              {th("hosts", "Hosts")}
              <th>Tipo</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => {
              const aiv = aiMap.get(g.key);
              return (
                <Fragment key={g.key}>
                  <tr className="row" onClick={() => setOpen(open === g.key ? null : g.key)}>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <Tier t={g.tier} /> <span className="small muted">{g.score}</span>
                    </td>
                    <td className="title-cell">
                      <b>{g.title}</b>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 3 }}>
                        {g.exploitAvailable && <span className="tag tag-exploit">Exploit público</span>}
                        {g.cve.slice(0, 3).map((c) => (
                          <span key={c} className="tag">
                            {c}
                          </span>
                        ))}
                        {g.cve.length > 3 && <span className="tag">+{g.cve.length - 3}</span>}
                      </div>
                    </td>
                    <td>
                      <SevBadge s={g.severity} />
                    </td>
                    <td className="num">{g.cvss ?? "–"}</td>
                    <td className="num">{g.hosts.length}</td>
                    <td className="small muted">{g.category}</td>
                  </tr>
                  {open === g.key && (
                    <tr className="detail">
                      <td colSpan={6}>
                        <div className="detail-grid">
                          <div>
                            <h4>
                              Impacto si no se soluciona {aiv && <span className="ai-label">IA</span>}
                            </h4>
                            <p>{aiv?.impacto ?? g.impact}</p>
                          </div>
                          <div>
                            <h4>
                              Cómo solucionarlo {aiv && <span className="ai-label">IA</span>}
                            </h4>
                            <p>{aiv?.recomendacion ?? (g.solution || "Ver recomendación del fabricante.")}</p>
                          </div>
                          {g.description && (
                            <div>
                              <h4>Descripción del escáner</h4>
                              <p className="muted">{g.description}</p>
                            </div>
                          )}
                          <div>
                            <h4>
                              Hosts afectados ({g.hosts.length}) · plazo {TIER_INFO[g.tier].plazo.toLowerCase()}
                            </h4>
                            <p className="muted small">{g.hosts.join(", ")}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {!rows.length && (
              <tr>
                <td colSpan={6} className="muted" style={{ textAlign: "center", padding: 24 }}>
                  No hay vulnerabilidades con esos filtros.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
