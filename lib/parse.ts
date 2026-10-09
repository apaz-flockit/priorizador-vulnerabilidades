import * as XLSX from "@e965/xlsx";
import { detectColumns } from "./rules.ts";

export type Row = Record<string, unknown>;

/**
 * Lee CSV, XLS o XLSX y devuelve filas como objetos.
 * Busca automáticamente la fila de encabezados (algunos escáneres, como Qualys,
 * agregan líneas de metadatos arriba) y elige la hoja con más datos reconocibles.
 */
export function parseSpreadsheet(data: ArrayBuffer | string, fileName: string): Row[] {
  const isCsv = /\.(csv|txt|tsv)$/i.test(fileName);
  let input = data;
  if (isCsv && typeof data !== "string") {
    // Decodificar el texto nosotros: UTF-8 y, si hay caracteres inválidos, Windows-1252 (Excel en español)
    let text = new TextDecoder("utf-8").decode(data);
    if (text.includes("\uFFFD")) text = new TextDecoder("windows-1252").decode(data);
    input = text.replace(/^\uFEFF/, "");
  }
  const wb =
    typeof input === "string"
      ? XLSX.read(input, { type: "string", raw: false, dense: true })
      : XLSX.read(new Uint8Array(input), { type: "array", raw: false, dense: true });

  let best: Row[] = [];
  let bestScore = -1;
  for (const name of wb.SheetNames) {
    const matrix = XLSX.utils.sheet_to_json<unknown[]>(wb.Sheets[name], { header: 1, defval: "", blankrows: false });
    if (!matrix.length) continue;
    // Buscar en las primeras 30 filas la que más se parezca a un encabezado
    let headerIdx = 0;
    let headerScore = -1;
    for (let i = 0; i < Math.min(30, matrix.length); i++) {
      const cells = (matrix[i] as unknown[]).map((c) => String(c ?? "").trim()).filter(Boolean);
      const score = Object.keys(detectColumns(cells)).length;
      if (score > headerScore) {
        headerScore = score;
        headerIdx = i;
      }
    }
    const headers = (matrix[headerIdx] as unknown[]).map((h, j) => String(h ?? "").trim() || `Columna ${j + 1}`);
    const rows: Row[] = matrix.slice(headerIdx + 1).map((r) => {
      const o: Row = {};
      headers.forEach((h, j) => (o[h] = (r as unknown[])[j] ?? ""));
      return o;
    });
    const score = headerScore * 1000 + rows.length;
    if (score > bestScore) {
      bestScore = score;
      best = rows;
    }
  }
  return best;
}
