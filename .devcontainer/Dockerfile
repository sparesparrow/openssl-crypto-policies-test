FROM fedora:41

# Install necessary packages
RUN dnf update -y && dnf install -y \
    openssl \
    openssl-devel \
    tcpdump \
    net-tools \
    wireshark-cli \
    ShellCheck \
    crypto-policies-scripts \
    gnutls-utils \
    git \
    nc \
    which \
    psmisc \
    procps-ng \
    iproute \
    bind-utils \
    lsof \
    strace \
    bats \
    tree \
    jq \
    vim

# Create the vscode user
RUN useradd -m -s /bin/bash -u 1000 vscode \
    && mkdir -p /home/vscode/.config \
    && chown -R vscode:vscode /home/vscode

# Set working directory
WORKDIR /workspace

# Create logs directory
RUN mkdir -p /workspace/.devcontainer/logs && \
    chown -R vscode:vscode /workspace

# Set environment variables
ENV SHELL=/bin/bash
ENV EDITOR="code --wait"
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV PATH=/workspace/bin:$PATH

# Switch to non-root user
USER vscode 