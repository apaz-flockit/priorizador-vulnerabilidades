"use client";

import { useRef, useState } from "react";

export default function Uploader({ onFile, onSample, loading }: { onFile: (f: File) => void; onSample: () => void; loading: boolean }) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  return (
    <>
      <div
        className={`dropzone ${over ? "over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          const f = e.dataTransfer.files?.[0];
          if (f) onFile(f);
        }}
      >
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
          <path d="M14 3v5h5M12 18v-6M9 15l3-3 3 3" />
        </svg>
        <h2>Arrastrá tu reporte de vulnerabilidades</h2>
        <p>CSV, XLS o XLSX exportado de Nessus, Qualys, OpenVAS, Rapid7, Defender u otra herramienta.</p>
        <div className="actions" style={{ justifyContent: "center" }}>
          <button className="btn btn-primary" onClick={() => input.current?.click()} disabled={loading}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Procesando…" : "Elegir archivo"}
          </button>
          <button className="btn" onClick={onSample} disabled={loading}>
            Probar con un ejemplo
          </button>
        </div>
        <input
          ref={input}
          type="file"
          accept=".csv,.tsv,.txt,.xls,.xlsx,.xlsm,.ods"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) onFile(f);
            e.target.value = "";
          }}
        />
      </div>
      <div className="feature-row">
        <div className="feature">
          <b>Detección automática de columnas</b>
          <span>Reconoce nombre, severidad, CVSS, CVE, CWE, host, solución y exploit, en inglés o castellano.</span>
        </div>
        <div className="feature">
          <b>Priorización P1 a P4</b>
          <span>Puntaje 0-100 según CVSS, exploit público, criticidad del activo, tipo de vulnerabilidad y alcance.</span>
        </div>
        <div className="feature">
          <b>Plan de remediación</b>
          <span>Agrupa vulnerabilidades que se resuelven con la misma acción y muestra cuánto riesgo elimina cada una.</span>
        </div>
        <div className="feature">
          <b>Impacto con IA</b>
          <span>Opcional: Claude explica el impacto de negocio y arma un resumen ejecutivo. Exportable a PDF.</span>
        </div>
      </div>
    </>
  );
}
