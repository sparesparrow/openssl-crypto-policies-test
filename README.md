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
├── setup.sh                # Test environment setup script
├── test.sh                 # Main test script 
└── README.md              # This file 
```

## Adding New Tests
1. Add test function to test.sh
2. Update documentation if needed
3. Run shellcheck to ensure code quality  
4. Test in development container
5. Submit pull request

## Contributing
1. Fork the repository
2. Create feature branch  
3. Commit changes
4. Push to branch
5. Create pull request 

This setup provides a complete development environment with:

1. Development Container:
- Based on Fedora 41
- Includes all required tools
- Configured with helpful VS Code extensions
- Runs with privileged access for network configuration

2. VS Code Integration:  
- Custom tasks for common operations
- Debug configurations
- Shell script linting
- Formatted saving  
- Helpful workspace settings

3. GitHub Actions:
- Automated testing on Fedora 41  
- Shell script linting
- Test artifact collection
- Runs on every push and pull request

4. Developer Experience:
- One-click container setup  
- Integrated debugging
- Easy test execution  
- Packet capture analysis
- Code quality checks

Key features:
1. Easy setup: Just open in VS Code with Dev Containers 
2. Integrated testing: Run tests directly from VS Code
3. Debugging support: Built-in configurations
4. Code quality: Automatic linting and formatting
5. CI/CD: Automated testing and artifact collection
