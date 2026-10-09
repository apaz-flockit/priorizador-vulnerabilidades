import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Priorizador de Vulnerabilidades",
  description: "Subí un reporte de vulnerabilidades (CSV, XLS o XLSX) y obtené la priorización, el impacto y el plan de remediación.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
