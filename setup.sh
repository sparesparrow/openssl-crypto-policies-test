#!/bin/bash

# OpenSSL Crypto-policies Compliance Test Script
# Verifies that TLS connections honor the system-wide crypto policies
# Target: Fedora 41
# Dependencies: openssl, tcpdump

set -e

# Handshake states enumeration
declare -r HND_SUCCESS=0      # Handshake completed
declare -r HND_CLIENT_HELLO=1 # Rejected at ClientHello
declare -r HND_SERVER_HELLO=2 # Rejected at ServerHello
declare -r HND_CIPHER_SPEC=3  # Rejected at ChangeCipherSpec (TLS 1.2)

# TLS version constants
declare -A TLS_VERSIONS=(
    ["SSL3"]="0x0300"
    ["TLS1.0"]="0x0301"
    ["TLS1.1"]="0x0302"
    ["TLS1.2"]="0x0303"
    ["TLS1.3"]="0x0304"
)

# Environment setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR=$(mktemp -d "/tmp/$(basename "$0").XXXXXX")
TCPDUMP_FILE="${TEMP_DIR}/capture.pcap"
SERVER_PORT=4433
SERVER_PID=""
TCPDUMP_PID=""
ORIGINAL_POLICY=""

# Logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "${TEMP_DIR}/test.log"
}

error() {
    log "ERROR: $1" >&2
    exit 1
}

# Argument processing with getopts
usage() {
    cat <<EOF
Usage: $0 [-l|--list] [-h|--help] [TEST_NAME]
Tests OpenSSL compliance with system crypto-policies

Options:
    -l, --list     List available tests
    -h, --help     Show this help message
    TEST_NAME      Optional: Run specific test case

Available tests:
    test_default_client_send_no_hello_if_weak_srv_cert
    test_default_server_rejects_client_ChangeCipherSpec
    test_legacy_server_allows_tls_version_downgrade_to_client_max_supported_version
EOF
    exit 1
}

process_args() {
    OPTS=$(getopt -o lh --long list,help -n "$0" -- "$@")
    if [ $? -ne 0 ]; then usage; fi
    eval set -- "$OPTS"

    while true; do
        case "$1" in
        -l | --list)
            list_tests
            exit 0
            ;;
        -h | --help) usage ;;
        --)
            shift
            break
            ;;
        *) error "Internal error!" ;;
        esac
    done
}

# Handshake state monitoring
monitor_handshake() {
    local packet_file="$1"
    local current_state=$HND_CLIENT_HELLO

    # Read raw packets without tshark dependency
    dd if="$packet_file" bs=1 skip=40 2>/dev/null | while read -r -n 1 byte; do
        # Look for TLS record layer
        if [[ $(printf "%02x" "'$byte") == "16" ]]; then
            read -r -n 2 version
            read -r -n 1 type
            case $(printf "%02x" "'$type") in
            "01") # ClientHello
                current_state=$HND_CLIENT_HELLO
                ;;
            "02") # ServerHello
                current_state=$HND_SERVER_HELLO
                ;;
            "14") # ChangeCipherSpec
                current_state=$HND_CIPHER_SPEC
                ;;
            "04") # NewSessionTicket/Finished
                if [ "$current_state" = "$HND_CIPHER_SPEC" ]; then
                    current_state=$HND_SUCCESS
                fi
                ;;
            esac
        fi
    done
    return $current_state
}

# Environment setup
setup() {
    local profile=$1
    local expected_result=$2

    # Create working directory
    mkdir -p "${TEMP_DIR}"/{certs,logs}

    # Store original policy
    ORIGINAL_POLICY=$(update-crypto-policies --show)

    # Set requested crypto policy
    update-crypto-policies --set "$profile"

    # Generate test certificates
    openssl req -x509 -newkey rsa:2048 -keyout "${TEMP_DIR}/certs/strong.key" \
        -out "${TEMP_DIR}/certs/strong.crt" -days 1 -nodes \
        -subj "/CN=localhost" 2>/dev/null

    openssl req -x509 -newkey rsa:1024 -keyout "${TEMP_DIR}/certs/weak.key" \
        -out "${TEMP_DIR}/certs/weak.crt" -days 1 -nodes \
        -subj "/CN=localhost" 2>/dev/null

    # Generate weak DH params
    openssl dhparam -out "${TEMP_DIR}/certs/weak_dh.pem" 1024 2>/dev/null

    # Start packet capture
    tcpdump -i lo port $SERVER_PORT -w "$TCPDUMP_FILE" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 1

    # Create PID file
    echo $$ >"${TEMP_DIR}/test.pid"

    return "$expected_result"
}

cleanup() {
    # Kill running processes
    [ -n "$SERVER_PID" ] && kill $SERVER_PID 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill $TCPDUMP_PID 2>/dev/null || true

    # Restore original policy
    [ -n "$ORIGINAL_POLICY" ] && update-crypto-policies --set "$ORIGINAL_POLICY"

    # Remove temp directory
    [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}

# Test Case 1
test_default_client_send_no_hello_if_weak_srv_cert() {
    setup "DEFAULT" $HND_CLIENT_HELLO
    local expected_state=$HND_CLIENT_HELLO

    # Start server with weak certificate
    openssl s_server -cert "${TEMP_DIR}/certs/weak.crt" \
        -key "${TEMP_DIR}/certs/weak.key" \
        -accept $SERVER_PORT -www &>"${TEMP_DIR}/logs/server.log" &
    SERVER_PID=$!
    sleep 1

    # Try to connect with TLS 1.3 client
    openssl s_client -connect localhost:$SERVER_PORT -tls1_3 \
        &>"${TEMP_DIR}/logs/client.log" </dev/null
    local client_rc=$?

    monitor_handshake "$TCPDUMP_FILE"
    local actual_state=$?

    # Verify client rejected before sending ClientHello
    [ $actual_state -eq $expected_state ] && [ $client_rc -ne 0 ]
    return $?
}

# Test Case 2
test_default_server_rejects_client_ChangeCipherSpec() {
    setup "DEFAULT" $HND_CIPHER_SPEC
    local expected_state=$HND_CIPHER_SPEC

    # Start server with TLS 1.2
    openssl s_server -cert "${TEMP_DIR}/certs/strong.crt" \
        -key "${TEMP_DIR}/certs/strong.key" \
        -accept $SERVER_PORT -tls1_2 &>"${TEMP_DIR}/logs/server.log" &
    SERVER_PID=$!
    sleep 1

    # Connect with client forcing weak DH
    openssl s_client -connect localhost:$SERVER_PORT -tls1_2 \
        -cipher "EDH" -dhparam "${TEMP_DIR}/certs/weak_dh.pem" \
        &>"${TEMP_DIR}/logs/client.log" </dev/null
    local client_rc=$?

    monitor_handshake "$TCPDUMP_FILE"
    local actual_state=$?

    # Verify server rejected during ChangeCipherSpec
    [ $actual_state -eq $expected_state ] && [ $client_rc -ne 0 ]
    return $?
}

# Test Case 3
test_legacy_server_allows_tls_version_downgrade_to_client_max_supported_version() {
    setup "LEGACY" $HND_SUCCESS
    local expected_state=$HND_SUCCESS

    # Start server allowing all versions
    openssl s_server -cert "${TEMP_DIR}/certs/strong.crt" \
        -key "${TEMP_DIR}/certs/strong.key" \
        -accept $SERVER_PORT -tls1_1 &>"${TEMP_DIR}/logs/server.log" &
    SERVER_PID=$!
    sleep 1

    # Connect with TLS 1.1 client
    openssl s_client -connect localhost:$SERVER_PORT -tls1_1 \
        &>"${TEMP_DIR}/logs/client.log" </dev/null
    local client_rc=$?

    monitor_handshake "$TCPDUMP_FILE"
    local actual_state=$?

    # Verify handshake completed with TLS 1.1
    [ $actual_state -eq $expected_state ] && [ $client_rc -eq 0 ] &&
        grep -q "Protocol.*TLSv1.1" "${TEMP_DIR}/logs/client.log"
    return $?
}

list_tests() {
    declare -F | grep '^declare -f test_' | cut -d' ' -f3
}

main() {
    # Must run as root
    [ "$EUID" -ne 0 ] && error "This script must be run as root"

    # Process arguments
    process_args "$@"

    # Set up cleanup trap
    trap cleanup EXIT

    # Run tests
    declare -A TEST_RESULTS
    if [ $# -eq 0 ]; then
        # Run all tests
        for test in $(list_tests); do
            log "Running $test..."
            if $test; then
                TEST_RESULTS[$test]="PASS"
            else
                TEST_RESULTS[$test]="FAIL"
            fi
        done
    else
        # Run specified test
        if declare -F "$1" >/dev/null; then
            log "Running $1..."
            if $1; then
                TEST_RESULTS[$1]="PASS"
            else
                TEST_RESULTS[$1]="FAIL"
            fi
        else
            error "Unknown test: $1"
        fi
    fi

    # Print results
    echo -e "\nTest Results:"
    echo "=============="
    for test in "${!TEST_RESULTS[@]}"; do
        printf "%-70s %s\n" "$test" "${TEST_RESULTS[$test]}"
    done
}

main "$@"
