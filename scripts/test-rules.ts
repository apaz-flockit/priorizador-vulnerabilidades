import { readFileSync } from "node:fs";
import { parseSpreadsheet } from "../lib/parse.ts";
import { analyze } from "../lib/rules.ts";

for (const f of ["public/ejemplo-vulnerabilidades.csv", "public/ejemplo-vulnerabilidades.xlsx"]) {
  const buf = readFileSync(f);
  const rows = parseSpreadsheet(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength), f);
  const r = analyze(rows, f);
  console.log(`\n== ${f}: ${rows.length} filas, ${r.findings.length} hallazgos, ${r.groups.length} vulns, ${r.actions.length} acciones`);
  console.log("columnas:", r.columns, "warnings:", r.warnings);
  if (f.endsWith(".csv")) {
    for (const g of r.groups) console.log(g.tier, String(g.score).padStart(3), g.severity.padEnd(11), g.category.padEnd(38), g.hosts.length, g.title);
    console.log("\nACCIONES");
    for (const a of r.actions) console.log(a.tier, String(a.riskReduction).padStart(5) + "%", a.vulnCount, a.hosts, a.action);
  }
}
