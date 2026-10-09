"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AnalysisResult, Severity } from "@/lib/types.ts";
import { SEVERITIES } from "@/lib/types.ts";

export const SEV_VAR: Record<Severity, string> = {
  Crítica: "var(--sev-critica)",
  Alta: "var(--sev-alta)",
  Media: "var(--sev-media)",
  Baja: "var(--sev-baja)",
  Informativa: "var(--sev-info)",
};

const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text)",
  fontSize: 12.5,
};
const axisTick = { fill: "var(--text-2)", fontSize: 12 };

export function SeverityChart({ result }: { result: AnalysisResult }) {
  const data = SEVERITIES.map((s) => ({
    name: s,
    hallazgos: result.findings.filter((f) => f.severity === s).length,
    vulns: result.groups.filter((g) => g.severity === s).length,
  }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 16, right: 8, left: -18, bottom: 0 }} barCategoryGap="28%">
        <CartesianGrid vertical={false} stroke="var(--border)" />
        <XAxis dataKey="name" tick={axisTick} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={axisTick} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: "var(--surface-2)" }}
          contentStyle={tooltipStyle}
          formatter={(v, n) => [v, n === "hallazgos" ? "Hallazgos" : "Vulnerabilidades únicas"]}
        />
        <Bar isAnimationActive={false} dataKey="hallazgos" radius={[4, 4, 0, 0]} label={{ position: "top", fill: "var(--text-2)", fontSize: 12 }}>
          {data.map((d) => (
            <Cell key={d.name} fill={SEV_VAR[d.name]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function CategoryChart({ result }: { result: AnalysisResult }) {
  const map = new Map<string, number>();
  result.findings
    .filter((f) => f.severity !== "Informativa")
    .forEach((f) => map.set(f.category, (map.get(f.category) ?? 0) + 1));
  const data = Array.from(map, ([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 30 + 20)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }} barCategoryGap={4}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={190} tick={axisTick} axisLine={false} tickLine={false} />
        <Tooltip cursor={{ fill: "var(--surface-2)" }} contentStyle={tooltipStyle} formatter={(v) => [v, "Hallazgos"]} />
        <Bar isAnimationActive={false} dataKey="value" fill="var(--accent)" radius={[0, 4, 4, 0]} label={{ position: "right", fill: "var(--text-2)", fontSize: 12 }} />
      </BarChart>
    </ResponsiveContainer>
  );
}
