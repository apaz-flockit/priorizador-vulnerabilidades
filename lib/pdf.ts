import type { AiResult, AnalysisResult, Severity } from "./types.ts";
import { SEVERITIES } from "./types.ts";
import { TIER_INFO } from "./rules.ts";

type RGB = [number, number, number];
const SEV_RGB: Record<Severity, RGB> = {
  Crítica: [208, 59, 59],
  Alta: [236, 131, 90],
  Media: [250, 178, 25],
  Baja: [42, 120, 214],
  Informativa: [138, 137, 132],
};

/** Genera y descarga el informe en PDF (todo en el navegador). */
export async function downloadPdf(r: AnalysisResult, ai: AiResult | null) {
  const { jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const M = 14;
  let y = 18;

  const lastY = () => (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY;
  const ensure = (h: number) => {
    if (y + h > 280) {
      doc.addPage();
      y = 18;
    }
  };
  const h2 = (t: string) => {
    ensure(14);
    doc.setFont("helvetica", "bold").setFontSize(13).setTextColor(20);
    doc.text(t, M, y);
    y += 6;
  };
  const para = (t: string, size = 10) => {
    doc.setFont("helvetica", "normal").setFontSize(size).setTextColor(50);
    const lines = doc.splitTextToSize(t, W - 2 * M);
    ensure(lines.length * 4.6);
    doc.text(lines, M, y);
    y += lines.length * 4.6 + 2;
  };

  // Encabezado
  doc.setFont("helvetica", "bold").setFontSize(18).setTextColor(15);
  doc.text("Informe de priorización de vulnerabilidades", M, y);
  y += 7;
  doc.setFont("helvetica", "normal").setFontSize(9).setTextColor(110);
  doc.text(`Archivo: ${r.fileName}   ·   Generado: ${new Date().toLocaleString("es-AR")}`, M, y);
  y += 9;

  // KPIs
  const hosts = new Set(r.findings.map((f) => f.host)).size;
  const count = (s: Severity) => r.findings.filter((f) => f.severity === s).length;
  const kpis: [string, string][] = [
    ["Hallazgos", String(r.findings.length)],
    ["Vulnerabilidades únicas", String(r.groups.length)],
    ["Hosts afectados", String(hosts)],
    ["Prioridad P1", String(r.groups.filter((g) => g.tier === "P1").length)],
  ];
  const kw = (W - 2 * M - 9) / 4;
  kpis.forEach(([label, val], i) => {
    const x = M + i * (kw + 3);
    doc.setDrawColor(220).setFillColor(248, 248, 246).roundedRect(x, y, kw, 18, 2, 2, "FD");
    doc.setFont("helvetica", "bold").setFontSize(15).setTextColor(15).text(val, x + 4, y + 9);
    doc.setFont("helvetica", "normal").setFontSize(8).setTextColor(100).text(label, x + 4, y + 14.5);
  });
  y += 25;

  // Distribución por criticidad (barra apilada con etiquetas)
  h2("Distribución por criticidad");
  const total = r.findings.length || 1;
  let x = M;
  const bw = W - 2 * M;
  for (const s of SEVERITIES) {
    const w = (count(s) / total) * bw;
    if (w <= 0) continue;
    doc.setFillColor(...SEV_RGB[s]).rect(x, y, Math.max(w - 0.6, 0.4), 6, "F");
    x += w;
  }
  y += 10;
  doc.setFontSize(9).setTextColor(60);
  doc.text(SEVERITIES.map((s) => `${s}: ${count(s)}`).join("     "), M, y);
  y += 8;

  if (ai) {
    h2("Resumen ejecutivo");
    para(ai.resumenEjecutivo);
    if (ai.riesgosPrincipales.length) {
      h2("Riesgos principales si no se remedia");
      ai.riesgosPrincipales.forEach((t) => para(`- ${t}`));
    }
  }

  // Plan de remediación
  h2("Plan de remediación (qué atacar primero)");
  autoTable(doc, {
    startY: y,
    margin: { left: M, right: M },
    head: [["Prior.", "Acción", "Vulns", "Hosts", "Riesgo que elimina", "Plazo"]],
    body: r.actions.map((a) => [a.tier, a.action, a.vulnCount, a.hosts, `${a.riskReduction}%`, TIER_INFO[a.tier].plazo]),
    styles: { fontSize: 8, cellPadding: 1.8 },
    headStyles: { fillColor: [40, 40, 40] },
    columnStyles: { 0: { cellWidth: 13, fontStyle: "bold" }, 2: { cellWidth: 13 }, 3: { cellWidth: 13 }, 4: { cellWidth: 24 }, 5: { cellWidth: 30 } },
  });
  y = lastY() + 10;

  // Detalle de vulnerabilidades
  const aiMap = new Map((ai?.vulnerabilidades ?? []).map((v) => [v.key, v]));
  h2("Detalle de vulnerabilidades");
  autoTable(doc, {
    startY: y,
    margin: { left: M, right: M },
    head: [["Prior.", "Vulnerabilidad", "Criticidad", "CVSS", "Hosts", "Impacto si no se soluciona"]],
    body: r.groups
      .filter((g) => g.severity !== "Informativa")
      .map((g) => [
        `${g.tier}\n${g.score}`,
        `${g.title}\n${g.category}${g.cve.length ? "\n" + g.cve.slice(0, 3).join(", ") : ""}${g.exploitAvailable ? "\nExploit público" : ""}`,
        g.severity,
        g.cvss ?? "-",
        g.hosts.length,
        aiMap.get(g.key)?.impacto ?? g.impact,
      ]),
    styles: { fontSize: 7.5, cellPadding: 1.6, valign: "top" },
    headStyles: { fillColor: [40, 40, 40] },
    columnStyles: { 0: { cellWidth: 12, fontStyle: "bold" }, 1: { cellWidth: 58 }, 2: { cellWidth: 18 }, 3: { cellWidth: 11 }, 4: { cellWidth: 11 } },
    didParseCell: (d) => {
      if (d.section === "body" && d.column.index === 2) {
        const s = d.cell.raw as Severity;
        if (SEV_RGB[s]) d.cell.styles.textColor = s === "Media" ? [150, 100, 0] : SEV_RGB[s];
        d.cell.styles.fontStyle = "bold";
      }
    },
  });

  // Pie de página
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8).setTextColor(140);
    doc.text(`Página ${i} de ${pages}`, W - M, 290, { align: "right" });
    doc.text(ai ? "Clasificación por reglas + análisis de impacto con IA" : "Clasificación por reglas", M, 290);
  }

  doc.save(`informe-vulnerabilidades-${new Date().toISOString().slice(0, 10)}.pdf`);
}
