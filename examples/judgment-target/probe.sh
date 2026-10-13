set -eu
/bin/sh /input/app.sh guest > /work/guest.stdout
/bin/sh /input/app.sh admin > /work/admin.stdout
record() {
    printf 'TARGET %s bytes ' "$1"
    /usr/bin/base64 -w0 "/work/$1.stdout"
    printf '\n'
    while IFS= read -r line || [ -n "$line" ]; do
        printf 'TARGET %s stdout %s\n' "$1" "$line"
    done < "/work/$1.stdout"
}
record guest
record admin
if ! printf 'ENTRY request-handler\nDATA private-record\n' | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'CONTROL admin failed\nCHECK complete\n'
    exit 0
fi
printf 'CONTROL admin passed\n'
if printf 'ENTRY request-handler\nDATA private-record\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE unauthorized-read\n'
elif printf 'ENTRY request-handler\nDENIED\n' | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE access-denied\n'
else
    printf 'ORACLE unknown-response\n'
fi
printf 'CHECK complete\n'
