import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/** Le indica al frontend si el análisis con IA está disponible y si pide código de acceso. */
export function GET() {
  return NextResponse.json({
    ai: Boolean(process.env.ANTHROPIC_API_KEY),
    requiresAccessCode: Boolean(process.env.ACCESS_CODE),
  });
}
