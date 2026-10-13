set -eu
/bin/sh /input/app.sh leak guest > /work/guest.stdout
/bin/sh /input/app.sh leak admin > /work/admin.stdout
printf 'TARGET guest stdout ENTRY leak\n'
if ! printf 'ENTRY leak\nTOKEN bridge-key\n' | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'CONTROL admin failed\nCHECK complete\n'
    exit 0
fi
printf 'CONTROL admin passed\n'
if printf 'ENTRY leak\nTOKEN bridge-key\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE leak-accepted\n'
elif printf 'ENTRY leak\nDENIED\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE leak-denied\n'
else
    printf 'ORACLE unknown\n'
fi
printf 'CHECK complete\n'
