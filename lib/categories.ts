/**
 * Base de conocimiento de categorías de vulnerabilidad.
 * Cada categoría define cómo detectarla (CWE / palabras clave), el impacto si no
 * se soluciona y qué problemas se resuelven al atacarla.
 */
export interface CategoryDef {
  name: string;
  cwe: number[];
  keywords: RegExp;
  bonus: number; // puntos extra de prioridad por naturaleza de la categoría
  impact: string;
  solves: string[];
}

export const CATEGORIES: CategoryDef[] = [
  {
    name: "Ejecución remota de código",
    cwe: [94, 95, 502, 77, 78, 917, 1336],
    keywords:
      /remote code execution|\brce\b|code execution|deserializ|log4j|log4shell|ms17-010|eternalblue|bluekeep|arbitrary code|command execution|ejecuci[oó]n remota/i,
    bonus: 12,
    impact:
      "Un atacante puede ejecutar código en el servidor y tomar control total del equipo: robo de datos, instalación de ransomware y uso del equipo para moverse al resto de la red.",
    solves: [
      "Evita la toma de control remoto de servidores",
      "Reduce el riesgo de ransomware",
      "Corta un punto de entrada para movimiento lateral",
    ],
  },
  {
    name: "Inyección (SQL / comandos)",
    cwe: [89, 90, 91, 643, 943, 611, 564],
    keywords: /sql injection|inyecci[oó]n|injection|\bsqli\b|xxe|xml external entit|ldap injection|nosql/i,
    bonus: 10,
    impact:
      "Permite leer, modificar o borrar datos de la base de datos (clientes, credenciales, transacciones) y en algunos casos ejecutar comandos en el servidor.",
    solves: [
      "Protege la confidencialidad e integridad de la base de datos",
      "Evita fuga masiva de datos personales",
      "Reduce exposición legal y regulatoria por filtraciones",
    ],
  },
  {
    name: "Cross-Site Scripting (XSS)",
    cwe: [79, 80, 83, 87],
    keywords: /cross[- ]site scripting|\bxss\b/i,
    bonus: 3,
    impact:
      "Un atacante puede ejecutar scripts en el navegador de los usuarios para robar sesiones, suplantar identidades o modificar lo que ven en la aplicación.",
    solves: [
      "Evita el robo de sesiones de usuarios",
      "Protege la reputación de la aplicación web",
    ],
  },
  {
    name: "Autenticación y credenciales",
    cwe: [287, 798, 521, 307, 259, 522, 256, 384, 613, 1391, 1392],
    keywords:
      /default (password|credential|account)|weak password|contrase[ñn]a|password|credential|brute.?force|authentication bypass|anonymous (login|access)|null session|hard.?coded|sin autenticaci|autenticaci/i,
    bonus: 8,
    impact:
      "Permite acceder a sistemas con credenciales débiles, por defecto o sin autenticar, obteniendo acceso legítimo aparente y difícil de detectar.",
    solves: [
      "Cierra accesos no autorizados con credenciales débiles o por defecto",
      "Reduce el riesgo de suplantación de identidad",
      "Mejora el cumplimiento de políticas de contraseñas",
    ],
  },
  {
    name: "Control de acceso y privilegios",
    cwe: [284, 285, 862, 863, 269, 250, 639, 732, 266, 276],
    keywords:
      /privilege escalation|escalada de privilegios|elevation of privilege|access control|unauthori[sz]ed access|idor|insecure direct object|permission|permisos/i,
    bonus: 7,
    impact:
      "Un usuario o atacante con acceso limitado puede obtener privilegios de administrador o acceder a información de otros usuarios.",
    solves: [
      "Evita escaladas de privilegios",
      "Asegura la segregación de datos entre usuarios",
    ],
  },
  {
    name: "Recorrido de rutas / inclusión de archivos",
    cwe: [22, 23, 35, 73, 98, 434],
    keywords: /path traversal|directory traversal|file inclusion|\blfi\b|\brfi\b|arbitrary file (read|upload)|file upload/i,
    bonus: 6,
    impact:
      "Permite leer archivos sensibles del servidor (configuración, claves) o subir archivos maliciosos que luego se ejecutan.",
    solves: [
      "Protege archivos de configuración y secretos del servidor",
      "Evita la carga de webshells",
    ],
  },
  {
    name: "SSRF / CSRF",
    cwe: [918, 352],
    keywords: /server[- ]side request forgery|\bssrf\b|cross[- ]site request forgery|\bcsrf\b|\bxsrf\b/i,
    bonus: 4,
    impact:
      "Permite forzar al servidor o al usuario a ejecutar peticiones no deseadas, accediendo a servicios internos o realizando acciones en nombre de la víctima.",
    solves: [
      "Protege servicios internos y metadatos de nube",
      "Evita acciones no autorizadas en nombre de los usuarios",
    ],
  },
  {
    name: "Software desactualizado / sin soporte",
    cwe: [1104, 1329, 937, 1035],
    keywords:
      /unsupported|end of life|\beol\b|obsolete|outdated|out of date|desactualizad|sin soporte|update|upgrade|actualizaci|security patch|missing patch|ms\d{2}-\d{3}|kb\d{6,}|version .* (prior|before|<)|< ?\d+\.\d+/i,
    bonus: 4,
    impact:
      "El software sin parches tiene vulnerabilidades públicas conocidas, muchas con exploits disponibles. Es uno de los vectores de ataque más usados por su facilidad.",
    solves: [
      "Elimina vulnerabilidades públicas con exploits conocidos",
      "Recupera soporte del fabricante y actualizaciones de seguridad",
      "Mejora el cumplimiento de gestión de parches (ISO 27001, PCI DSS)",
    ],
  },
  {
    name: "Criptografía y TLS/SSL",
    cwe: [295, 326, 327, 328, 310, 311, 319, 320, 757, 916],
    keywords:
      /\bssl\b|\btls\b|cipher|certificate|certificado|\bcrypt|encrypt|cifrado|\bmd5\b|\bsha-?1\b|\brc4\b|\bdes\b|3des|sweet32|poodle|heartbleed|beast|logjam|freak|self[- ]signed|cleartext|texto plano|unencrypted|hsts/i,
    bonus: 0,
    impact:
      "Las comunicaciones o datos pueden ser interceptados o descifrados (ataques man-in-the-middle), exponiendo credenciales e información sensible en tránsito.",
    solves: [
      "Protege credenciales y datos en tránsito",
      "Evita ataques de intermediario (MITM)",
      "Elimina advertencias de seguridad en navegadores y clientes",
    ],
  },
  {
    name: "Exposición de información",
    cwe: [200, 209, 532, 538, 548, 497, 215, 359],
    keywords:
      /information disclosure|info(rmation)? leak|exposure|exposici[oó]n|disclos|banner|version (detection|disclosure)|enumerat|fingerprint|internal ip|stack trace/i,
    bonus: 0,
    impact:
      "Revela información interna (versiones, rutas, usuarios, IPs) que un atacante usa para planificar ataques más precisos.",
    solves: ["Reduce la información disponible para el reconocimiento", "Evita filtraciones de datos menores"],
  },
  {
    name: "Configuración insegura",
    cwe: [16, 2, 15, 1188, 942, 1021, 614, 1004],
    keywords:
      /misconfig|configuraci[oó]n|default (config|install|page)|directory listing|directory indexing|smb signing|header|cabecera|clickjacking|cors|cookie|debug|trace method|http trace|open (relay|resolver)|snmp|telnet|\bftp\b|exposed (service|port|admin)|admin (panel|interface)/i,
    bonus: 1,
    impact:
      "Configuraciones por defecto o permisivas amplían la superficie de ataque y facilitan otros ataques (reconocimiento, robo de cookies, relay de credenciales).",
    solves: [
      "Reduce la superficie de ataque expuesta",
      "Aplica hardening según buenas prácticas (CIS Benchmarks)",
      "Dificulta el reconocimiento por parte de atacantes",
    ],
  },
  {
    name: "Denegación de servicio",
    cwe: [400, 770, 674, 835, 1333, 406, 404],
    keywords: /denial of service|\bdos\b|\bddos\b|denegaci[oó]n de servicio|resource exhaustion|redos|crash/i,
    bonus: 0,
    impact:
      "Un atacante puede dejar el servicio no disponible, provocando interrupción del negocio y pérdida de ingresos.",
    solves: ["Mejora la disponibilidad de los servicios", "Reduce el riesgo de interrupciones del negocio"],
  },
];

export const OTHER_CATEGORY: CategoryDef = {
  name: "Otras",
  cwe: [],
  keywords: /$^/,
  bonus: 0,
  impact:
    "Debilidad de seguridad que puede ser aprovechada combinada con otras. Requiere análisis específico para dimensionar su impacto.",
  solves: ["Reduce la superficie de ataque general"],
};

export function getCategory(name: string): CategoryDef {
  return CATEGORIES.find((c) => c.name === name) ?? OTHER_CATEGORY;
}

export function classifyCategory(title: string, description: string, cwe: string[]): CategoryDef {
  const cweNums = cwe.map((c) => parseInt(c.replace(/\D/g, ""), 10)).filter((n) => !isNaN(n));
  for (const cat of CATEGORIES) {
    if (cweNums.some((n) => cat.cwe.includes(n))) return cat;
  }
  // El título es más confiable que la descripción: primero se evalúa solo el título.
  for (const cat of CATEGORIES) if (cat.keywords.test(title)) return cat;
  for (const cat of CATEGORIES) if (cat.keywords.test(description)) return cat;
  return OTHER_CATEGORY;
}
