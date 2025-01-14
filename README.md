# OpenSSL Crypto-policies Test Suite

Test suite for verifying OpenSSL TLS connections respect system-wide crypto-policies settings on Fedora 41.

## Development Environment Setup

### Prerequisites 
- VS Code
- Docker  
- Dev Containers extension for VS Code

### Getting Started
1. Clone the repository 
2. Open in VS Code
3. When prompted, click "Reopen in Container"
4. VS Code will build and start the development container

### Available Tasks
- `Setup Test Environment`: Prepares the test environment
- `Run All Tests`: Executes all available tests
- `Run Selected Test`: Runs a specific test (provides selection menu)  
- `List Available Tests`: Shows all available test cases
- `Start Packet Capture`: Begins packet capture for analysis
- `Clean Environment`: Removes test environment
- `Lint Shell Scripts`: Runs shellcheck on all shell scripts

### Debugging
Two debug configurations are available:
- `Debug Test Script`: Debug the main test script  
- `Debug Setup Script`: Debug the setup script

### Test Environment
The test environment uses:
- Server Address: 127.0.0.1:4433  
- Client Address: 127.0.0.2
- Packet capture for all localhost traffic
- Separate certificates for different test scenarios

### Manual Testing
```bash
# Setup environment 
sudo ./setup.sh

# Load test environment
source work/test_env.sh

# Run all tests
sudo ./test.sh  

# Run specific test
sudo ./test.sh test_name

# List available tests  
sudo ./test.sh -l

# Clean up
sudo ./setup.sh clean  
```

### GitHub Actions
The repository includes CI/CD pipeline that:
- Runs on Fedora 41
- Performs shellcheck linting  
- Executes all tests
- Uploads test artifacts (logs, packet captures)

### Files Structure
```
.
├── .devcontainer/
│   └── devcontainer.json    # Development container configuration 
├── .github/
│   └── workflows/ 
│       └── test.yml         # GitHub Actions workflow
├── .vscode/
│   ├── launch.json          # Debug configurations
│   ├── settings.json        # VS Code workspace settings 
│   └── tasks.json          # VS Code tasks
├── testplan.txt            # Test environment design
├── test.sh                 # Main test script 
└── README.md              # This file 
```
[./testplan.txt.md](./testplan.txt.md)


