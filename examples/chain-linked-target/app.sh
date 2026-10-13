# Synthetic two-primitive fixture; execute only in the isolated worker.
route=$1
role=$2
case "$route" in
    leak)
        printf 'ENTRY leak\n'
        if [ "$role" = admin ]; then
            printf 'TOKEN bridge-key\n'
        else
            printf 'TOKEN bridge-key\n'
        fi
        ;;
    redeem)
        token=$3
        printf 'ENTRY redeem\n'
        if [ "$token" != bridge-key ]; then
            printf 'DENIED\n'
        elif [ "$role" = admin ]; then
            printf 'SECRET vault-record\n'
        else
            printf 'SECRET vault-record\n'
        fi
        ;;
    *) printf 'DENIED\n' ;;
esac
