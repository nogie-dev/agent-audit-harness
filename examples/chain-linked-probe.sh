set -eu
/bin/sh /input/app.sh leak guest > /work/first.stdout
if ! printf 'ENTRY leak\nTOKEN bridge-key\n' | /usr/bin/cmp -s - /work/first.stdout; then
    printf 'ORACLE chain-denied\nCHECK complete\n'
    exit 0
fi
printf 'TARGET first stdout ENTRY leak\n'
state=$(/usr/bin/sed -n 's/^TOKEN //p' /work/first.stdout)
printf 'CHAIN producer base64 '
printf '%s' "$state" | /usr/bin/base64 -w0
printf '\n'
printf 'CHAIN consumer base64 '
printf '%s' "$state" | /usr/bin/base64 -w0
printf '\n'
/bin/sh /input/app.sh redeem guest "$state" > /work/second.stdout
printf 'TARGET second stdout ENTRY redeem\n'
if printf 'ENTRY redeem\nSECRET vault-record\n' | /usr/bin/cmp -s - /work/second.stdout; then
    printf 'ORACLE chain-accepted\n'
else
    printf 'ORACLE chain-denied\n'
fi
/bin/sh /input/app.sh redeem guest invalid-state > /work/control.stdout
if printf 'ENTRY redeem\nDENIED\n' | /usr/bin/cmp -s - /work/control.stdout; then
    printf 'CHAIN control denied\n'
else
    printf 'CHAIN control accepted\n'
fi
printf 'TARGET second bytes '
/usr/bin/base64 -w0 /work/second.stdout
printf '\n'
printf 'CHECK complete\n'
