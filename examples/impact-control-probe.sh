set -eu
/bin/sh /input/app.sh admin > /work/admin.stdout
while IFS= read -r line || [ -n "$line" ]; do
    printf 'TARGET admin stdout %s\n' "$line"
done < /work/admin.stdout
if printf 'ENTRY request-handler\nDATA private-record\n' | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'ORACLE control-authorized\n'
else
    printf 'ORACLE control-denied\n'
fi
printf 'CHECK complete\n'
