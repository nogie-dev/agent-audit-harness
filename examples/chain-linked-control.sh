set -eu
/bin/sh /input/app.sh redeem admin bridge-key > /work/admin.stdout
printf 'TARGET admin stdout ENTRY redeem\n'
/bin/sh /input/app.sh redeem guest invalid-state > /work/invalid.stdout
if printf 'ENTRY redeem\nSECRET vault-record\n' | /usr/bin/cmp -s - /work/admin.stdout &&
   printf 'ENTRY redeem\nDENIED\n' | /usr/bin/cmp -s - /work/invalid.stdout; then
    printf 'ORACLE control-authorized\n'
else
    printf 'ORACLE control-failed\n'
fi
printf 'CHECK complete\n'
