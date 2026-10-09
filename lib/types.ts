export type Severity = "Crítica" | "Alta" | "Media" | "Baja" | "Informativa";

export const SEVERITIES: Severity[] = ["Crítica", "Alta", "Media", "Baja", "Informativa"];

export type PriorityTier = "P1" | "P2" | "P3" | "P4";

export interface Finding {
  id: number;
  title: string;
  severity: Severity;
  cvss: number | null;
  cve: string[];
  cwe: string[];
  host: string;
  port: string;
  description: string;
  solution: string;
  exploitAvailable: boolean;
  assetCritical: boolean;
  category: string;
  score: number; // 0-100
  tier: PriorityTier;
}

/** Una vulnerabilidad única (agrupada por título) con todos sus hosts afectados. */
export interface VulnGroup {
  key: string;
  title: string;
  severity: Severity;
  cvss: number | null;
  cve: string[];
  cwe: string[];
  category: string;
  hosts: string[];
  findings: number;
  exploitAvailable: boolean;
  score: number;
  tier: PriorityTier;
  description: string;
  solution: string;
  impact: string; // impacto si no se soluciona (reglas, puede reemplazarse por IA)
  aiImpact?: string;
  aiRecommendation?: string;
}

/** Acción de remediación: atacar una causa resuelve varios hallazgos. */
export interface RemediationAction {
  key: string;
  action: string;
  category: string;
  vulnCount: number;
  findings: number;
  hosts: number;
  maxScore: number;
  tier: PriorityTier;
  riskReduction: number; // % del riesgo total que elimina
  solves: string[]; // problemas que se solucionan
  vulnTitles: string[];
}

export interface ColumnMap {
  title?: string;
  severity?: string;
  cvss?: string;
  cve?: string;
  cwe?: string;
  host?: string;
  port?: string;
  description?: string;
  solution?: string;
  exploit?: string;
  assetCriticality?: string;
}

export interface AnalysisResult {
  fileName: string;
  columns: ColumnMap;
  findings: Finding[];
  groups: VulnGroup[];
  actions: RemediationAction[];
  totalRisk: number;
  warnings: string[];
}

export interface AiResult {
  resumenEjecutivo: string;
  riesgosPrincipales: string[];
  vulnerabilidades: { key: string; impacto: string; recomendacion: string }[];
}
