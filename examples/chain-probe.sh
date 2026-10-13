set -eu
/bin/sh /input/app.sh guest > /work/first.stdout
if ! printf 'ENTRY request-handler\nDATA private-record\n' | /usr/bin/cmp -s - /work/first.stdout; then
    printf 'ORACLE chain-state-denied\nCHECK complete\n'
    exit 0
fi
printf 'TARGET first stdout ENTRY request-handler\n'
state=$(/usr/bin/sed -n 's/^DATA //p' /work/first.stdout)
printf 'CHAIN producer base64 '
printf '%s' "$state" | /usr/bin/base64 -w0
printf '\n'
printf 'CHAIN consumer base64 '
printf '%s' "$state" | /usr/bin/base64 -w0
printf '\n'
/bin/sh /input/app.sh "$state" > /work/second.stdout
printf 'TARGET second stdout ENTRY request-handler\n'
if printf 'ENTRY request-handler\nDATA private-record\n' | /usr/bin/cmp -s - /work/second.stdout; then
    printf 'ORACLE chain-state-accepted\n'
else
    printf 'ORACLE chain-state-denied\n'
fi
/bin/sh /input/app.sh invalid-state > /work/control.stdout
if printf 'ENTRY request-handler\nDENIED\n' | /usr/bin/cmp -s - /work/control.stdout; then
    printf 'CHAIN control denied\n'
else
    printf 'CHAIN control accepted\n'
fi
printf 'CHECK complete\n'
