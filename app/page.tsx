"use client";

import { useCallback, useEffect, useState } from "react";
import Uploader from "@/components/Uploader";
import Dashboard from "@/components/Dashboard";
import { parseSpreadsheet } from "@/lib/parse.ts";
import { analyze } from "@/lib/rules.ts";
import type { AiResult, AnalysisResult } from "@/lib/types.ts";

export default function Home() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [ai, setAi] = useState<AiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [config, setConfig] = useState<{ ai: boolean; requiresAccessCode: boolean }>({ ai: false, requiresAccessCode: false });

  useEffect(() => {
    fetch("/api/config")
      .then((r) => r.json())
      .then(setConfig)
      .catch(() => {});
  }, []);

  const handleFile = useCallback(async (file: File) => {
    setError(null);
    setAi(null);
    if (file.size > 50 * 1024 * 1024) {
      setError("El archivo supera los 50 MB.");
      return;
    }
    setLoading(true);
    try {
      // Todo el procesamiento ocurre en el navegador: el archivo no se sube a ningún servidor.
      const buf = await file.arrayBuffer();
      const rows = parseSpreadsheet(buf, file.name);
      const r = analyze(rows, file.name);
      if (!r.findings.length) throw new Error(r.warnings[0] ?? "El archivo no contiene filas reconocibles.");
      setResult(r);
    } catch (e) {
      setError(`No se pudo leer el archivo: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSample = useCallback(async () => {
    const res = await fetch("/ejemplo-vulnerabilidades.csv");
    const blob = await res.blob();
    handleFile(new File([blob], "ejemplo-vulnerabilidades.csv"));
  }, [handleFile]);

  return (
    <main className="container">
      {!result ? (
        <>
          <header className="header">
            <div>
              <h1>Priorizador de Vulnerabilidades</h1>
              <p>Clasificación por tipo, criticidad, impacto y plan de remediación a partir de tu reporte.</p>
            </div>
          </header>
          {error && <div className="alert alert-error">{error}</div>}
          <Uploader onFile={handleFile} onSample={loadSample} loading={loading} />
        </>
      ) : (
        <Dashboard
          result={result}
          ai={ai}
          setAi={setAi}
          config={config}
          onReset={() => {
            setResult(null);
            setAi(null);
          }}
        />
      )}
      <p className="footer">El archivo se procesa en tu navegador. Para el análisis con IA solo se envía un resumen de las vulnerabilidades, sin IPs ni hosts.</p>
    </main>
  );
}
