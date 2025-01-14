
Weak parameters can be sent by both the client and server in any state of the TLS handshake process.
The peer that received such "weak" parameters is supposed to terminate the process immediately, 
and indicate a handshake error unless a profile "LEGACY" has been set globally on the system by "update-crypto-policies".

What constitutes "weak" parameters?

A "weak" ClientHello is characterized by:
1. Protocol version <= TLS 1.1
2. Offering weak cipher suites (e.g., RC4, DES, 3DES)
3. Offering weak key exchange methods (RSA key transport instead of DHE/ECDHE)
4. Offering weak signature algorithms (e.g., SHA1)

A "weak" server certificate is characterized by:
1. RSA key size < 2048 bits or ECC key size < 256 bits
2. Signature algorithm using SHA1 or MD5
3. Using outdated parameters for DH key exchange (< 2048 bits)

Test setup

Assuming that target OS (where test.sh will run) is Fedora 41 with program update-crypto-policies installed, the test script will perform following actions for each test case selected:
1. Create a temporary directory under /tmp/ where all output created by test execution will be placed.
2. Setup the crypto-policies profile globally to 
3. Generate two certificates with openssl (weak-srv/)  define client/server role to test after the profile has been set, and an expected result of the test execution

$HND_REJECT_REASON is an enumerable with value that is equal to the current state of the TLS Handshake process (an enumerable variable) at time when one of the peers rejected the handshake.
- Value can be one of:
- CLIENT_HELLO = 1 (before client initiates Hello)
- SERVER_HELLO = 2 (before server responds with a Hello)
- CIPHER_SPEC = 3 
    - (reachable only if TLSv1.2 negotiated, in TLSv1.3 this is part of the SERVER_HELLO)
- SUCCESS = 0 
    - (TLS handshake completed)

Test cases

The three most critical test cases are each covering one "weakness" that might be brought to the handshake negotiation process by either s_client or s_server, and results in action (accept/reject) based on the combination of current crypto-policies profile and the s_server/s_client parameters used for attempting to establish an encrypted communication session.

## |==|DEFAULT Profile| ==> s_any
  * PASS 
    - $HND_REJECT_REASON equals not SUCCESS && both peers support TLS1.3 && SNI is encrypted with weak cipher although strong ciphers available 
  * FAIL:
    - $HND_REJECT_REASON equals SUCCESS
      && handshake negotiated with at least one of following parameters:
        - 3DES, RC4, DH with parameters < 2048 bits, RSA with key size < 2048 bits, DSA (all key sizes), TLSv1.0, TLSv1.1

## |==|LEGACY Profile| ==> s_any
  * PASS:
  * FAIL:
    - $HND_REJECT_REASON equals SUCCESS
        && Handshake negotiated to use at least one of the following ciphersuites and protocols:
        - DH with parameters < 1024 bits, RSA with key size < 1024 bits, Camellia, ARIA, SEED, IDEA, Integrity only ciphersuites, TLS Ciphersuites using SHA-384 HMAC, AES-CCM8, all ECC curves incompatible with TLS 1.3, including secp256k1, IKEv1 (since RHEL-8)
            - These ciphersuites and protocols are available but disabled in all crypto policy levels. They can be enabled only by explicit configuration of individual applications
        - DES (since RHEL-7), All export grade ciphersuites (since RHEL-7), MD5 in signatures (since RHEL-7), SSLv2 (since RHEL-7), SSLv3 (since RHEL-8), All ECC curves < 224 bits (since RHEL-6), All binary field ECC curves (since RHEL-6)
            - These ciphersuites and protocols are completely removed from the core crypto libraries. They are either not present at all in the sources or their support is disabled during the build so it cannot be used by applications in any way

## |==|DEFAULT Profile| ==> s_client:

### test_default_client_send_no_hello_if_weak_srv_cert => Test case 1
    - Critical because it tests client-side certificate validation
    - Prevents connections before any sensitive data is transmitted
    - Validates crypto-policies' role in certificate validation

#### Expected result
  * When:
    - Client prevents sending Client Hello if no supported version/cipher/algorithm has been found in server certificate.
  * PASS:
    - s_server is started "weak" && $HND_REJECT_REASON equals CLIENT_HELLO or CIPHER_SPEC
  * FAIL: 
    - s_server started with "weak" certificate && $HND_REJECT_REASON not equals CLIENT_HELLO 
                                               && s_client supports "-tls1_3"

## |==|DEFAULT Profile| ==> s_server:

### test_default_server_rejects_client_ChangeCipherSpec => Test case 2
    - Critical because it tests server-side protocol enforcement
    - Ensures server actively rejects weak security parameters
    - Validates handshake-level security controls

#### Expected result
  * When:
    - Server supports TLSv1.3, allows downgrade to TLSv1.2, but then rejects ChangeCipherSpec received from client
  * PASS:
    - CIPHER_SPEC offer version >= TLSv1.2
  * FAIL: 
    - $HND_REJECT_REASON equals not CIPHER_SPEC && SERVER_HELLO negotiated TLSv1.2 && s_client only accepts DH with 1024 bits 

## |==|LEGACY Profile| ==> s_server:
### test_legacy_server_allows_tls_version_downgrade_to_client_max_supported_version => Test case 3
    - Most critical because it tests the fundamental security boundary between profiles
    - Verifies that LEGACY profile permits version downgrade while DEFAULT prevents it
    - Tests both client and server behavior in one scenario
#### Expected result
  * When:
    - Both client and server supports TLS 1.1
  * PASS:
    - $HND_REJECT_REASON equals SUCCESS && CLIENT_HELLO/CIPHER_SPEC attempted with offer to downgrade to "weak" version
  * FAIL: 
    - $HND_REJECT_REASON equals SUCCESS
    && both peers supports TLS 1.2 and/or TLS 1.3
    && "weak" TLS version negotiated despite downgrade to a stronger version also available

## |==|LEGACY Profile| ==> s_client:

PASS if s_server allowed version downgrade && $HND_REJECT_REASON equals SUCCESS

    test_legacy_server_allows_tls_version_downgrade_to_client_max_supported_version
        Most critical because it tests the fundamental security boundary between profiles
        Verifies that LEGACY profile permits version downgrade while DEFAULT prevents it
        Tests both client and server behavior in one scenario

    test_default_client_send_no_hello_if_weak_srv_cert
        Critical because it tests client-side certificate validation
        Prevents connections before any sensitive data is transmitted
        Validates crypto-policies' role in certificate validation