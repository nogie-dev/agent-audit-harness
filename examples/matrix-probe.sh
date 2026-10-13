set -eu
case "$1" in
    release)
        /usr/bin/cc -std=c11 -O2 -DAUDIT_GUARD=0 /input/app.c -o /work/app
        configuration='CONFIG optimization=enabled guard=0'
        ;;
    guarded)
        /usr/bin/cc -std=c11 -O0 -DAUDIT_GUARD=1 /input/app.c -o /work/app
        configuration='CONFIG optimization=disabled guard=1'
        ;;
    *) exit 2 ;;
esac
/work/app guest > /work/guest.stdout
/work/app admin > /work/admin.stdout
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
if ! printf '%s\nENTRY request-handler\nDATA private-record\n' "$configuration" | /usr/bin/cmp -s - /work/admin.stdout; then
    printf 'CONTROL admin failed\nCHECK complete\n'
    exit 0
fi
printf 'CONTROL admin passed\n'
if printf '%s\nENTRY request-handler\nDATA private-record\n' "$configuration" | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE unauthorized-read\n'
elif printf '%s\nENTRY request-handler\nDENIED\n' "$configuration" | /usr/bin/cmp -s - /work/guest.stdout; then
    printf 'ORACLE access-denied\n'
else
    printf 'ORACLE unknown-response\n'
fi
printf 'CHECK complete\n'
