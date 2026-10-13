set -eu
/bin/sh /input/app.sh leak admin > /work/admin.stdout
printf 'TARGET admin stdout ENTRY leak\n'
if printf 'ENTRY leak\nTOKEN bridge-key\n' | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'ORACLE setup-ready\n'
else
    printf 'ORACLE setup-failed\n'
fi
printf 'CHECK complete\n'
