# Benign containment fixture; intended to execute only inside the worker.
set -eu
[ "${AUDIT_WORKER:-}" = 1 ]
[ "$(id -u)" = 65532 ]
[ "${HOME}" = /tmp ]
[ -z "${AUDIT_TEST_CREDENTIAL:-}" ]
[ -z "${OPENAI_API_KEY:-}" ]
[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]
[ -z "${SSH_AUTH_SOCK:-}" ]
[ ! -e /var/run/docker.sock ]
[ ! -e /root/.aws/credentials ]
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status
# Only loopback and no route to an external destination under network=none.
[ "$(wc -l < /proc/net/route)" -eq 1 ]
if touch /input/host-write-probe 2>/dev/null; then exit 41; fi
if touch /etc/host-write-probe 2>/dev/null; then exit 42; fi
printf 'scratch evidence\n' > /work/witness
cat /work/witness
printf 'CONTAINMENT_CHECKS_PASSED\n'
