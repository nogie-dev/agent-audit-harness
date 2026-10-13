set -eu
/bin/sh /input/app.sh redeem guest bridge-key > /work/guest.stdout
/bin/sh /input/app.sh redeem admin bridge-key > /work/admin.stdout
printf 'TARGET guest stdout ENTRY redeem\n'
if ! printf 'ENTRY redeem\nSECRET vault-record\n' | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'CONTROL admin failed\nCHECK complete\n'
    exit 0
fi
printf 'CONTROL admin passed\n'
if printf 'ENTRY redeem\nSECRET vault-record\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE redeem-accepted\n'
elif printf 'ENTRY redeem\nDENIED\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE redeem-denied\n'
else
    printf 'ORACLE unknown\n'
fi
printf 'CHECK complete\n'
