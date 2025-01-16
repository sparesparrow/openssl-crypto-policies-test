#!/usr/bin/env bash
# test.sh - OpenSSL Crypto-policies Test Suite
# Tests TLS connection behavior under different crypto-policies profiles on Fedora 41

set -euo pipefail
IFS=$'\n\t'

# Constants and Global Variables
readonly SUCCESS=0
readonly CLIENT_HELLO=1
readonly SERVER_HELLO=2
readonly CIPHER_SPEC=3
readonly SERVER_PORT=4433

TEMP_DIR=
CERT_DIR=
LOG_DIR=
ORIGINAL_POLICY=

declare -A TEST_RESULTS
declare -i HANDSHAKE_STATE=0

export CLIENT_WEAK_TLS_VERSION=false
export CLIENT_WEAK_CIPHERSPEC=false
export SERVER_WEAK_TLS_VERSION=false
export SERVER_WEAK_CERT=false
export LEGACY_CRYPTO_POLICY=false

export CRYPTO_POLICY_DEFAULT="DEFAULT"
export CRYPTO_POLICY_LEGACY="LEGACY"
export LATEST_TLS_VERSION="-tls1_3"
export DEPRECATED_TLS_VERSION="-tls1_1"

# Handshake state tracking
declare -A HANDSHAKE_STATE_MAP=(
    ["INITIAL"]="0"
    ["CLIENT_HELLO"]="1"
    ["SERVER_HELLO"]="2"
    ["CIPHER_SPEC"]="3"
    ["SUCCESS"]="4"
    ["REJECTED"]="5"
    ["TIMEOUT"]="6"
)

# Expected state transitions for each test type
declare -A EXPECTED_TRANSITIONS=(
    ["DEFAULT_STRONG"]="CLIENT_HELLO,SERVER_HELLO,CIPHER_SPEC,SUCCESS"
    ["DEFAULT_WEAK_CLIENT"]="CLIENT_HELLO,REJECTED"
    ["DEFAULT_WEAK_SERVER"]="CLIENT_HELLO,REJECTED"
    ["LEGACY_DOWNGRADE"]="CLIENT_HELLO,SERVER_HELLO,CIPHER_SPEC,SUCCESS"
)

usage() {
    cat <<EOF
Usage: $0 [-l|--list] [-h|--help] [TEST_NAME]
Tests OpenSSL compliance with system crypto-policies

Options:
    -l, --list     List available tests
    -h, --help     Show this help message
    TEST_NAME      Optional: Run only test cases specified

Available tests:

test_default_client_send_no_hello_if_weak_srv_cert
    -> Tests client rejection of weak server certificates
    -> Verifies rejection happens at CLIENT_HELLO or CIPHER_SPEC stage

test_default_server_rejects_client_ChangeCipherSpec
    -> Tests server rejection of weak cipher specifications
    -> Verifies rejection happens at CIPHER_SPEC stage with TLS 

test_legacy_server_allows_tls_version_downgrade
    -> Tests LEGACY profile version downgrade behavior
    -> Verifies successful downgrade to TLS 1.1
    -> Checks both handshake completion and protocol version
EOF
    exit 1
}


# Logging functions - Fixed SC2155 warning
log() {
    local level=$1
    shift
    local message
    message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    
    # Always print to stdout
    echo "$message"
    
    # Only write to log file if LOG_DIR is set and directory exists
    if [[ -n "${LOG_DIR:-}" ]] && [[ -d "$LOG_DIR" ]]; then
        echo "$message" >> "${LOG_DIR}/test.log"
    fi
}

error() {
    log "ERROR" "$@"
    cleanup
    exit 1
}

# Setup function - Updated to properly initialize directories
setup() {
    log "INFO" "=== Starting Test Environment Setup ==="
    
    log "INFO" "Validating system requirements..."
    if ! grep -q "Fedora 41" /etc/fedora-release 2>/dev/null; then
        error "System requirement: This script must be run on Fedora 41"
    fi
    log "INFO" "System version validated: Fedora 41"
    
    if [[ $EUID -ne 0 ]]; then
        error "System requirement: This script must be run as root"
    fi
    log "INFO" "Root privileges validated"
    
    # Initialize directories with proper error handling
    TEMP_DIR=$(mktemp -d) || error "Failed to create temporary directory"
    readonly TEMP_DIR
    
    CERT_DIR="${TEMP_DIR}/certs"
    readonly CERT_DIR
    mkdir -p "$CERT_DIR" || error "Failed to create certificate directory"
    
    LOG_DIR="${TEMP_DIR}/logs"
    readonly LOG_DIR
    mkdir -p "$LOG_DIR" || error "Failed to create log directory"
    
    log "INFO" "Created test directories in ${TEMP_DIR}"
    
    # Save original policy
    ORIGINAL_POLICY=$(update-crypto-policies --show) || error "Failed to get current crypto policy"
    readonly ORIGINAL_POLICY
    log "INFO" "Saved current crypto-policy: ${ORIGINAL_POLICY}"
    
    # Generate certificates
    log "INFO" "Generating test certificates..."
    generate_crt "strong" || error "Failed to generate strong certificate"
    generate_crt "weak" || error "Failed to generate weak certificate"
    log "INFO" "Generated test certificates in ${CERT_DIR}"
    
    log "INFO" "=== Test Environment Setup Completed ==="
}

# Certificate generation
generate_crt() {
    local cert_type=$1
    
    if [[ -z "$cert_type" ]] || [[ ! "$cert_type" =~ ^(strong|weak)$ ]]; then
        log "ERROR" "Invalid certificate type: $cert_type"
        return 1
    fi
    
    local key_size
    if [[ $cert_type == "strong" ]]; then
        key_size="2048"
    else
        key_size="1024"
    fi
    
    local cert_dir="${CERT_DIR}/${cert_type}"
    
    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"
    
    if ! openssl req -x509 -newkey "rsa:${key_size}" \
        -keyout "${cert_dir}/key.pem" \
        -out "${cert_dir}/cert.pem" \
        -days 1 -nodes \
        -subj "/CN=localhost" \
        -sha256 2>/dev/null; then
        log "ERROR" "Failed to generate ${cert_type} certificate"
        return 1
    fi
    
    chmod 600 "${cert_dir}/key.pem" "${cert_dir}/cert.pem"
    log "DEBUG" "Generated ${cert_type} certificate (${key_size} bits) in ${cert_dir}"
    return 0
}

# Server management functions
wait_for_server() {
    local max_attempts=10
    local attempt=1
    
    while ! nc -z localhost "$SERVER_PORT" >/dev/null 2>&1; do
        if ((attempt >= max_attempts)); then
            return 1
        fi
        sleep 1
        ((attempt++))
    done
    return 0
}

start_tls_server() {
    local cert_type=$1
    local options="${2:-}"
    local max_retries=3
    local retry_count=0
    
    if [[ -z "$cert_type" ]] || [[ ! "$cert_type" =~ ^(strong|weak)$ ]]; then
        log "ERROR" "Invalid certificate type: $cert_type"
        return 1
    fi
    
    local cert_path="${CERT_DIR}/${cert_type}"
    if [[ ! -d "$cert_path" ]]; then
        log "ERROR" "Certificate directory not found: $cert_path"
        return 1
    fi
    
    if nc -z localhost "$SERVER_PORT" 2>/dev/null; then
        log "WARNING" "Port $SERVER_PORT is in use, attempting to kill existing process"
        fuser -k "${SERVER_PORT}/tcp" || true
        sleep 1
    fi
    
    while ((retry_count < max_retries)); do
        log "INFO" "Starting OpenSSL server (attempt $((retry_count + 1))/${max_retries})"
        
        openssl s_server \
            -key "${cert_path}/key.pem" \
            -cert "${cert_path}/cert.pem" \
            -accept "$SERVER_PORT" \
            "${options}" >"${LOG_DIR}/server.log" 2>&1 &
        
        local server_pid=$!
        export SERVER_PID=$server_pid
        
        if wait_for_server; then
            log "INFO" "Server started successfully (PID: ${server_pid})"
            return 0
        fi
        
        log "WARNING" "Server failed to start, retrying..."
        kill "$server_pid" 2>/dev/null || true
        ((retry_count++))
        sleep 1
    done
    
    log "ERROR" "Failed to start server after ${max_retries} attempts"
    return 1
}

tls_client_connect() {
    local options="${1:-}"
    local expect_success="${2:-true}"
    local test_type="${3:-DEFAULT_STRONG}"
    local timeout_seconds=5
    
    log "INFO" "Testing client connection with options: ${options}"
    log "DEBUG" "Expected success: ${expect_success}"
    log "DEBUG" "Test type: ${test_type}"
    
    # Clear previous handshake state
    HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[INITIAL]}"
    
    # Start packet capture
    tshark -i lo -f "port ${SERVER_PORT}" -w "${LOG_DIR}/handshake.pcap" 2>/dev/null &
    local tshark_pid=$!
    
    sleep 1  # Allow tshark to initialize
    
    local connection_result
    if timeout "$timeout_seconds" openssl s_client -connect "localhost:${SERVER_PORT}" \
        "${options}" </dev/null >"${LOG_DIR}/client.log" 2>&1; then
        connection_result=0
    else
        connection_result=1
    fi
    
    # Clean up tshark
    kill "$tshark_pid" 2>/dev/null || true
    
    # Analyze the handshake with test type
    analyze_handshake_state "$test_type"
    
    # Determine test result
    if [[ "$expect_success" == "true" ]]; then
        return "$connection_result"
    else
        [[ $connection_result -eq 0 ]] && return 1 || return 0
    fi
}

# Enhanced handshake analysis with detailed state tracking
analyze_handshake_state() {
    local test_type="${1:-DEFAULT_STRONG}"
    local timeout=5
    local start_time
    start_time=$(date +%s)
    
    local expected_sequence="${EXPECTED_TRANSITIONS[$test_type]}"
    if [[ -z "$expected_sequence" ]]; then
        log "ERROR" "Unknown test type: $test_type"
        return 1
    fi
    
    local -A observed_states
    local current_state="INITIAL"
    
    while true; do
        local current_time
        current_time=$(date +%s)
        if ((current_time - start_time > timeout)); then
            HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[TIMEOUT]}"
            log "ERROR" "Handshake analysis timed out"
            return 1
        fi
        
        if ! "${observed_states[CLIENT_HELLO]:-false}" && \
           tshark -r "${LOG_DIR}/handshake.pcap" -Y "tls.handshake.type == 1" 2>/dev/null | grep -q .; then
            observed_states[CLIENT_HELLO]=true
            current_state="CLIENT_HELLO"
            HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[CLIENT_HELLO]}"
            log "DEBUG" "Observed CLIENT_HELLO"
        fi
        
        if ! "${observed_states[SERVER_HELLO]:-false}" && \
           tshark -r "${LOG_DIR}/handshake.pcap" -Y "tls.handshake.type == 2" 2>/dev/null | grep -q .; then
            observed_states[SERVER_HELLO]=true
            current_state="SERVER_HELLO"
            HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[SERVER_HELLO]}"
            
            local protocol_version
            protocol_version=$(tshark -r "${LOG_DIR}/handshake.pcap" -Y "tls.handshake.type == 2" -T fields -e tls.handshake.version 2>/dev/null)
            log "DEBUG" "Observed SERVER_HELLO with protocol version: $protocol_version"
            
            if [[ "$test_type" == "LEGACY_DOWNGRADE" && "$protocol_version" != "0x0302" ]]; then
                log "ERROR" "Unexpected protocol version in LEGACY_DOWNGRADE test"
                return 1
            fi
        fi
        
        if grep -q "SSL_connect:error" "${LOG_DIR}/client.log" 2>/dev/null; then
            current_state="REJECTED"
            HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[REJECTED]}"
            break
        fi
        
        if grep -q "SSL handshake has read" "${LOG_DIR}/client.log" 2>/dev/null; then
            current_state="SUCCESS"
            HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[SUCCESS]}"
            break
        fi
        
        sleep 0.1
    done
    
    HANDSHAKE_STATE="${HANDSHAKE_STATE_MAP[$current_state]}"
    
    # Validate against expected sequence
    if [[ "$expected_sequence" == *"$current_state"* ]]; then
        log "DEBUG" "Handshake completed with expected state: $current_state"
        return 0
    else
        log "ERROR" "Unexpected final state: $current_state (expected sequence: $expected_sequence)"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log "INFO" "=== Starting System Cleanup ==="
    
    log "INFO" "Terminating any remaining test processes..."
    if pkill -f "openssl s_server"; then
        log "INFO" "Terminated OpenSSL server processes"
    fi
    if pkill -f "tshark"; then
        log "INFO" "Terminated tshark processes"
    fi
    
    log "INFO" "Restoring original crypto-policy: ${ORIGINAL_POLICY}"
    if update-crypto-policies --set "$ORIGINAL_POLICY"; then
        log "INFO" "Successfully restored crypto-policy"
    else
        log "ERROR" "Failed to restore crypto-policy"
    fi
    
    log "INFO" "Removing temporary test directory: ${TEMP_DIR}"
    rm -rf "$TEMP_DIR"
    
    log "INFO" "=== System Cleanup Completed ==="
}

# Enhanced test_default_client_send_no_hello_if_weak_srv_cert function
test_default_client_send_no_hello_if_weak_srv_cert() {
    local test_name="DEFAULT Client Rejects Weak Server Certificate"
    log "INFO" "=== Starting Test: ${test_name} ==="
    
    log "INFO" "Setting crypto-policy to DEFAULT"
    update-crypto-policies --set DEFAULT
    
    log "INFO" "Starting server with weak certificate (1024-bit RSA)"
    if ! start_tls_server "weak"; then
        log "ERROR" "Failed to start server with weak certificate"
        TEST_RESULTS["$test_name"]="FAIL (Server start failed)"
        return 1
    fi
    
    log "INFO" "Testing TLS 1.2 capable client against weak server"
    tls_client_connect "-tls1_2" false "DEFAULT_WEAK_SERVER"
    
    log "INFO" "Terminating test server (PID: ${SERVER_PID})"
    kill "$SERVER_PID"
    
    # Enhanced validation of handshake state transitions
    case "${HANDSHAKE_STATE_MAP[$current_state]}" in
        "${HANDSHAKE_STATE_MAP[CLIENT_HELLO]}")
            log "INFO" "Connection rejected at CLIENT_HELLO stage"
            TEST_RESULTS["$test_name"]="PASS"
            ;;
        "${HANDSHAKE_STATE_MAP[CIPHER_SPEC]}")
            log "INFO" "Connection rejected at CIPHER_SPEC stage"
            TEST_RESULTS["$test_name"]="PASS"
            ;;
        "${HANDSHAKE_STATE_MAP[SUCCESS]}")
            log "ERROR" "Connection unexpectedly succeeded with weak server certificate"
            TEST_RESULTS["$test_name"]="FAIL (Unexpected success)"
            ;;
        *)
            log "ERROR" "Connection rejected at unexpected handshake stage ($current_state)"
            TEST_RESULTS["$test_name"]="FAIL (Unexpected rejection stage)"
            ;;
    esac
}

# Enhanced test_default_server_rejects_client_ChangeCipherSpec function
test_default_server_rejects_client_ChangeCipherSpec() {
    local test_name="DEFAULT Server Rejects Weak Cipher Spec"
    log "INFO" "=== Starting Test: ${test_name} ==="
    
    log "INFO" "Setting crypto-policy to DEFAULT"
    update-crypto-policies --set DEFAULT
    
    log "INFO" "Starting server with strong certificate"
    if ! start_tls_server "strong" "-tls1_3"; then
        log "ERROR" "Failed to start server"
        TEST_RESULTS["$test_name"]="FAIL (Server start failed)"
        return 1
    fi
    
    log "INFO" "Testing with TLS 1.2 and weak DH parameters"
    tls_client_connect "-tls1_2 -cipher DHE-RSA-AES128-SHA -dhparam 1024" false
    
    log "INFO" "Terminating test server (PID: ${SERVER_PID})"
    kill "$SERVER_PID"
    
    if [[ "$HANDSHAKE_STATE" == "CIPHER_SPEC" ]]; then
        log "INFO" "Connection rejected at cipher spec stage"
        TEST_RESULTS["$test_name"]="PASS"
    elif [[ "$HANDSHAKE_STATE" == "SUCCESS" ]]; then
        log "ERROR" "Connection unexpectedly succeeded with weak DH parameters"
        TEST_RESULTS["$test_name"]="FAIL (Unexpected success)"
    else
        log "ERROR" "Connection rejected at unexpected handshake stage (${HANDSHAKE_STATE})"
        TEST_RESULTS["$test_name"]="FAIL (Unexpected rejection stage)"
    fi
}

# Enhanced test_legacy_server_allows_tls_version_downgrade function
test_legacy_server_allows_tls_version_downgrade() {
    local test_name="LEGACY Server Allows Version Downgrade"
   
    log "INFO" "=== Starting Test: ${test_name} ==="
    
    log "INFO" "Setting crypto-policy to LEGACY"
    update-crypto-policies --set LEGACY
    
    log "INFO" "Starting server with all TLS versions enabled"
    if ! start_tls_server "strong" "-tls1_3 -tls1_2 -tls1_1"; then
        log "ERROR" "Failed to start server"
        TEST_RESULTS["$test_name"]="FAIL (Server start failed)"
        return 1
    fi
    
    log "INFO" "Testing with forced TLS 1.1"
    tls_client_connect "-tls1_1" true
    
    log "INFO" "Terminating test server (PID: ${SERVER_PID})"
    kill "$SERVER_PID"
    
    # Enhanced validation with handshake state checks
    if [[ "$HANDSHAKE_STATE" == "SUCCESS" ]]; then
        # Verify negotiated TLS version in client log
        if grep -q "Protocol  : TLSv1.1" "${LOG_DIR}/client.log"; then
            log "INFO" "Successfully downgraded to TLS 1.1"
            TEST_RESULTS["$test_name"]="PASS"
        else
            log "ERROR" "Negotiated TLS version does not match expected TLS 1.1"
            TEST_RESULTS["$test_name"]="FAIL (Wrong protocol version)"
        fi
    else
        log "ERROR" "Handshake was not successful (state: ${HANDSHAKE_STATE})"
        TEST_RESULTS["$test_name"]="FAIL (Handshake not successful)"
    fi
}

# Results reporting
print_results() {
    echo -e "\nTest Results Summary"
    echo "==================="
    for test in "${!TEST_RESULTS[@]}"; do
        printf "%-50s [%s]\n" "$test" "${TEST_RESULTS[$test]}"
    done
    local total=${#TEST_RESULTS[@]}
    local passed=0
    for result in "${TEST_RESULTS[@]}"; do
        [[ $result == "PASS" ]] && ((passed++))
    done
    echo -e "\nTotal Tests: ${total}"
    echo "Passed: ${passed}"
    echo "Failed: $((total - passed))"
}

# Main execution
main() {
    trap cleanup EXIT
    
    if [[ "${1:-}" == "-l" ]]; then
        echo "Available Tests:"
        declare -F | grep "^declare -f test_" | awk '{print $3}'
        exit 0
    fi
    
    setup
    
    if [[ $# -eq 0 ]]; then
        # Run all tests
        test_default_client_send_no_hello_if_weak_srv_cert
        test_default_server_rejects_client_ChangeCipherSpec
        test_legacy_server_allows_tls_version_downgrade
    else
        # Run specified tests
        for test_func in "$@"; do
            if [[ $(type -t "$test_func") == "function" ]]; then
                test_name=$(declare -f "$test_func" | grep "^test_" | awk '{print $1}' | sed 's/test_//')
                log "INFO" "Running $test_func..."
                if "$test_func"; then
                    TEST_RESULTS["$test_func"]="PASS"
                else
                    TEST_RESULTS["$test_func"]="FAIL"
                fi
            else
                log "WARNING" "Test function not found: ${test_func}"
            fi
        done
    fi
    
    print_results
}

main "$@"

