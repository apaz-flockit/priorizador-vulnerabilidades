# Priorizador de Vulnerabilidades

**App online: [priorizador-vulnerabilidades.vercel.app](https://priorizador-vulnerabilidades.vercel.app/)**

App web (Next.js) que lee un reporte de vulnerabilidades en **CSV, XLS o XLSX** y genera un reporte con:

- **Tipo de vulnerabilidad** (RCE, inyección, credenciales, TLS, software desactualizado, configuración, etc.).
- **Criticidad** (Crítica / Alta / Media / Baja / Informativa) a partir del CVSS y de la severidad del escáner.
- **Prioridad P1-P4** con puntaje 0-100 y plazo sugerido (7 / 30 / 90 días).
- **Impacto si no se soluciona** y **problemas que se resuelven** al atacar cada vulnerabilidad.
- **Plan de remediación**: agrupa las vulnerabilidades que se resuelven con la misma acción (ej. "Endurecer TLS" resuelve 3 vulnerabilidades en 10 hosts) y muestra qué % del riesgo total elimina cada una.
- **Análisis con IA (opcional)**: Claude redacta el impacto de negocio, la recomendación de cada vulnerabilidad y un resumen ejecutivo.
- **Descarga en PDF** del informe.

## Probar la app

1. Abrí https://priorizador-vulnerabilidades.vercel.app/
2. Hacé clic en **"Probar con un ejemplo"** (o subí tu propio CSV, XLS o XLSX).
3. Para el análisis con IA, hacé clic en **"Analizar impacto con IA"**. Pide un código de acceso: si querés probarlo, solicitáselo a Alberto Paz (alberto.paz@flockit.com.ar).

Sin el código podés usar todo lo demás (clasificación, priorización, plan de remediación y PDF); el código solo habilita el análisis con IA.

## Cómo funciona

1. El archivo se lee **en el navegador** (no se sube a ningún servidor).
2. Se detectan las columnas automáticamente (en inglés o castellano: `Name`, `Severity`, `CVSS`, `CVE`, `Host`, `Solution`, `Exploit Available`, `Criticidad Activo`, etc.). Funciona con exportaciones de Nessus, Qualys, OpenVAS, Rapid7 y otras.
3. Un **motor de reglas** (`lib/rules.ts` y `lib/categories.ts`) clasifica, puntúa y arma el plan de remediación.
4. Si está configurada la clave de Anthropic, el botón **"Analizar impacto con IA"** envía a `/api/analyze` un resumen de las 30 vulnerabilidades más prioritarias (**sin IPs ni hosts**, solo la cantidad).

### Puntaje de prioridad

`CVSS × 10` (o la severidad del escáner) + exploit público (+10) + activo crítico o de producción (+5) + tipo de vulnerabilidad (RCE, inyección y credenciales suman más) + alcance (cantidad de hosts, hasta +6). Por encima de 80 los puntos valen la mitad, para mantener el orden entre los casos graves.

| Prioridad | Puntaje | Plazo |
|---|---|---|
| P1 | ≥ 85 | Hasta 7 días |
| P2 | ≥ 65 | Hasta 30 días |
| P3 | ≥ 40 | Hasta 90 días |
| P4 | < 40 | Planificar o aceptar el riesgo |

## Correr en tu computadora

Requiere Node.js 20 o superior.

```bash
npm install
cp .env.example .env.local   # completá ANTHROPIC_API_KEY si querés usar la IA
npm run dev                  # http://localhost:3000
```

Otros comandos:

- `npm run build` y `npm start`: versión de producción.
- `npm run test:rules`: corre el motor de reglas sobre el archivo de ejemplo y muestra el resultado en consola.
- `npm run sample`: regenera `public/ejemplo-vulnerabilidades.csv` y `.xlsx` (requiere Python; `openpyxl` para el .xlsx).

## Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Clave de https://console.anthropic.com. Sin ella la app funciona solo con reglas. |
| `ANTHROPIC_MODEL` | No | Modelo de Claude (por defecto `claude-haiku-4-5`, más rápido; con `claude-sonnet-4-5` el análisis es más detallado pero puede tardar más). |
| `ACCESS_CODE` | No | Si la definís, el análisis con IA pide este código. Recomendado si la app es pública, para que nadie más gaste tu clave. |

## Despliegue

### Vercel (recomendado)

1. Subí el proyecto a GitHub.
2. En https://vercel.com → **Add New → Project** → importá el repo (detecta Next.js solo).
3. En **Settings → Environment Variables** cargá `ANTHROPIC_API_KEY` (y `ACCESS_CODE` si querés).
4. Deploy. Cada `git push` a `main` vuelve a publicar.

### Railway

1. En https://railway.com → **New Project → Deploy from GitHub repo**.
2. En **Variables** cargá `ANTHROPIC_API_KEY` (y `ACCESS_CODE`).
3. En **Settings → Networking** generá un dominio público.
   Railway detecta Next.js, corre `npm run build` y `npm start` (que usa la variable `PORT`).

## Estructura

```
app/page.tsx              Pantalla principal (carga del archivo)
app/api/analyze/route.ts  Análisis con IA (Claude)
app/api/config/route.ts   Indica si la IA está configurada
components/               Dashboard, gráficos y carga de archivos
lib/parse.ts              Lectura de CSV/XLS/XLSX y detección de encabezados
lib/rules.ts              Detección de columnas, criticidad, puntaje y plan de remediación
lib/categories.ts         Base de conocimiento: tipos, impacto y problemas que se resuelven
lib/pdf.ts                Generación del PDF
public/                   Archivos de ejemplo
```

Para ajustar la clasificación a tu organización, editá `lib/categories.ts` (palabras clave, CWE, textos de impacto) y los pesos de `scoreOf` en `lib/rules.ts`.
