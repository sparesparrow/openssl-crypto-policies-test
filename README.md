# OpenSSL Crypto-policies Test Plan
- Test plan for [assignment](./assignment.md)

## Environment Prerequisites
- Fedora 40+ or RHEL 8+
- Root access or sudo permissions for update-crypto-policies 
- OpenSSL command-line tools (s_client, s_server)
- tcpdump for network monitoring, tshark for packet inspection
- Free port 4433, no firewall on localhost

## Purpose of this test suite
- Ensure system enforces required security levels, preventing use of deprecated  protocols
- Verify applications work with security policies
- Ensure legacy systems can still connect when needed
- Test the behavior of OpenSSL when cryptographic policies are applied system-wide using `update-crypto-policies`

### What is `update-crypto-policies`?
* `update-crypto-policies` is a `Fedora`/`RHEL` system-wide cryptographic policy manager that:
1. Enforces consistent security levels across all cryptographic libraries
2. Provides predefined security profiles (DEFAULT, LEGACY, FUTURE, FIPS)
3. Configures allowed protocols, algorithms, and key sizes system-wide

#### Setting the profile
```bash
update-crypto-policies --set DEFAULT
```
 * updates system-wide crypto configuration to:
  - Disable older TLS versions (1.0/1.1)
  - Enforce minimum key sizes (RSA ≥ 2048 bits)
  - Restrict cipher suites to secure options
  - Set minimum requirements for all crypto operations

---

### Naming convention
The tests will be assigned a self-descriptive name, refering to specific edge case scenarios caused by combination of factors that have an impact on the system under test.

### Setup
- Each test is dependent on a specific setup logic that provides an environment where these factors will be arranged to have a distinction between parameter weaknesses that can come from either side of the connection. 
- Client and server capabilities will be reconfigured in a way that exactly one of them introduces a weak parameter, while the other peer is configured to be up to date and in compliance with the `DEFAULT` crypto-policy.
- The peer that received unsupported parameter is supposed to react with respect to the crypto-policies profile set globally on the system.

#### **`setup()`** and **`cleanup()`**
- There will be a generic setup logic that applies to all tests. Each test additionally defines own requirements for the setup, particularly by passing arguments to the `setup()` function.
  - After test execution, the `cleanup()` function shall reset these flags to their defaults (false). 

---

## Approach 

The plan is to separate the cases based on distinct sources of potential security violations:

### Client vs Server
* **Client** 
   - Weak ClientHello parameters (min/max supported TLS version, applicable cipher suites, key exchange methods, signature algorithms)
* **Server** 
   - Weak ServerHello or server certificate issues (key sizes, signature algorithms, DH parameters)

#### Weak parameters

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

### Verification Methods

1. **Packet Analysis:**
  * Capture TLS Handshake - tcpdump
    - `tshark -i lo -f "port ${SERVER_PORT}" -w "${LOG_DIR}/handshake.pcap"`
      - ClientHello message structure
      - ServerHello response
      - Certificate exchange
      - Key exchange parameters
  * Capture TLS Handshake - tshark
    - `tshark -i lo -f "tcp port 4433" -Y "tls.handshake.type == 1"`
      - ClientHello message structure
      - ServerHello response
      - Certificate exchange
      - Key exchange parameters
      
2. **OpenSSL Diagnostics:**
  - Detailed connection info from `s_client` and `s_server`:
    - start openssl with `-tlsextdebug` and `-state` parameters to get details of:
        - Protocol version
        - Negotiated cipher
        - Certificate chain
        - TLS extensions

## Test Cases Implemented

### 1. test_default_client_send_no_hello_if_weak_srv_cert
Purpose:
- Tests client-side certificate validation
- Prevents connections before sensitive data transmission
- Validates crypto-policies' role in certificate validation

Setup:
- DEFAULT crypto-policy profile
- Generated weak server certificate (RSA key size < 2048 bits)

Test Parameters:
- Server Certificate: RSA key < 2048 bits
- Client Configuration: TLS 1.3 capable
- Expected Handshake State: CLIENT_HELLO or CIPHER_SPEC

Success Criteria:
- Client prevents sending Client H ello when:
  - No supported version/cipher/algorithm found in server certificate
  - $HANDSHAKE_STATE equals CLIENT_HELLO or CIPHER_SPEC

Failure Conditions:
- $HANDSHAKE_STATE not equals CLIENT_HELLO when:
  - Server started with weak certificate AND
  - Client supports TLS 1.3

Cleanup:
- Remove temporary certificates
- Kill any remaining server processes
- Restore original crypto-policy

### 2. test_default_server_rejects_client_ChangeCipherSpec
Purpose:
- Tests server-side protocol enforcement
- Ensures **server actively rejects** weak security parameters
- Validates handshake-level security controls during cipher negotiation
- Verifies proper handling of TLS 1.2 downgrade attempts
Setup:
- `DEFAULT` crypto-policy profile
- Standard server certificate (RSA key size ≥ 2048 bits)
- Server configured to support TLS 1.3
Test Parameters:
- Server Configuration:
  - TLS 1.3 enabled
  - Downgrade to TLS 1.2 permitted
- Client Configuration:
  - DH parameters set to 1024 bits
  - Force TLS 1.2 negotiation
Success Criteria:
- Server properly rejects weak cipher specifications when:
  - CIPHER_SPEC offer version is TLS 1.2 or higher
### Setup
  - $HANDSHAKE_STATE equals CIPHER_SPEC
  - Server logs indicate rejection due to weak DH parameters
Failure Conditions:
- $HANDSHAKE_STATE not equals CIPHER_SPEC when:
  - `SERVER_HELLO` negotiated TLS 1.2 AND
  - Client only accepts DH with 1024 bits
Cleanup:
- Terminate server process
- Remove any temporary certificates
- Restore original crypto-policy

### 3. test_legacy_server_allows_tls_version_downgrade
Purpose:
- Tests fundamental security boundary between DEFAULT and LEGACY profiles
- Verifies correct version downgrade behavior in LEGACY profile
- Validates both client and server behavior in downgrade scenarios
- Ensures proper protocol version negotiation
Setup:
- LEGACY crypto-policy profile
- Standard server certificate (RSA key size ≥ 2048 bits)
- Both client and server must support TLS 1.1 minimum
Test Parameters:
- Server Configuration:
  - Multiple TLS versions enabled (1.1 through 1.3)
  - LEGACY profile active
- Client Configuration:
  - Maximum TLS version set to 1.1
  - Standard cipher suite selection
Success Criteria:
- Server allows protocol version downgrade when:
  - $HANDSHAKE_STATE equals SUCCESS AND
  - CLIENT_HELLO or CIPHER_SPEC attempted downgrade to weak version
- Successful negotiation to TLS 1.1 despite higher versions available
Failure Conditions:
- $HANDSHAKE_STATE equals SUCCESS when:
  - Both peers support TLS 1.2 and/or TLS 1.3 AND
  - Weak TLS version negotiated despite stronger version availability
- Connection rejection when downgrade should be permitted
- Negotiation to version higher than client maximum
Cleanup:
- Terminate server process
- Remove any temporary certificates
- Restore original crypto-policy
- Clean up any captured handshake data
Test State Monitoring:
- Track complete handshake process through all states
- Record protocol version at each stage
- Monitor cipher suite selection process
- Log all downgrade attempt details

