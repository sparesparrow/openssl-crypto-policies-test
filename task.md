
# SUMMARY
- *Test if crypto policy is respected in TLS connections made by OpenSSL.*

# OBJECTIVES:
  * understanding technology area
  * figuring out and design of test scenarios
  * shell scripting
  * problem solving

# SCOPE

Expected time investment is around 4 hours. It is fine to submit a partial solution if it seems it would take you more time to finish the assignment completely.

# ASSIGNMENT:

1. `Test plan design`

Prepare a test plan for assuring that TLS connections established by OpenSSL respect profile set by 'crypto-policies' [1]. Focus only on testing 'DEFAULT' and 'LEGACY' profiles [2] and TLS connections between OpenSSL testing tools s_client [3] and s_server [4].

Create a text file 'testplan.txt' containing a list of proposed test scenarios. Describe each scenario in a few sentences in order to explain what is supposed to be tested and how the proper/expected behavior is going to be verified.

2. `Implementation of a script`

Implement 3 most important scenarios in the shell/bash script 'test.sh'.

These are the requirements on the shell script:
  * Script works on RHEL-9, or Fedora 40+. Focus on just one of them, e.g., just Fedora 41, and state it clearly in the script.
  * Each test scenario is represented by a function (`choose appropriate name for the function).`
  * Script contains functions 'setup' and 'cleanup'. The first one should prepare the the system for the test execution (prepare necessary files, setup and start required services, etc.) while the latter should undo all changes done by the setup script and the test itself, therefore bringing the test system to original state (`i.e., the state in which the system was before running test.sh).`
  * When executed without parameters, the script should do the setup, execute all available (implemented) tests and perform the cleanup.
  * It is possible to specify individual tests (functions) to be executed as command line arguments (`specified with the respective function names).`
  * After all tests are executed, a short summary with test results is printed. The summary lists tests that were executed and respective test results (`PASS/FAIL).`
  * When invoked with the '-l' argument, the script `lists all available tests.`

Hints:
  * prepare a machine in advance, e.g., using VirtualBox - download and installation takes time
  * generate key and certificate: `openssl req -x509 -newkey rsa -keyout key.pem -out server.pem -days 365 -nodes -subj "/CN=localhost"`
  * run server: `openssl s_server -key key.pem -cert server.pem`
  * run client: `openssl s_client`

REFERENCE:
[1] https://access.redhat.com/articles/3666211
[2] man crypto-policies
[3] man s_client
[4] man s_server
