# Synthetic authorization fixture; execute only in the isolated worker.
serve_request() {
    role=$1
    printf 'ENTRY request-handler\n'
    printf 'DATA private-record\n'
}
serve_request "$1"
