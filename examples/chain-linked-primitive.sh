set -eu
/bin/sh /input/app.sh leak guest > /work/guest.stdout
printf 'TARGET guest stdout ENTRY leak\n'
if printf 'ENTRY leak\nTOKEN bridge-key\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE primitive-leaked\n'
else
    printf 'ORACLE primitive-denied\n'
fi
printf 'CHECK complete\n'
