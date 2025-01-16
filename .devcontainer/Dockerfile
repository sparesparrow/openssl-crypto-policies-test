FROM fedora:41

# Install necessary packages as root during build
USER root
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
    vim \
    sudo

# Create the vscode user and set up sudo with error handling
RUN if ! id vscode > /dev/null 2>&1; then \
    useradd -m -s /bin/bash -u 1000 vscode; \
    fi && \
    mkdir -p /home/vscode/.config && \
    echo "vscode ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/vscode && \
    echo "Defaults secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/workspace/bin" >> /etc/sudoers.d/vscode && \
    chmod 0440 /etc/sudoers.d/vscode && \
    chown -R vscode:vscode /home/vscode

# Configure sudo without password prompt for the vscode user
RUN echo "vscode ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/vscode && \
    echo "Defaults !requiretty" >> /etc/sudoers.d/vscode && \
    chmod 0440 /etc/sudoers.d/vscode

# Disable PAM for sudo
RUN sed -i 's/^@include common-auth/#@include common-auth/' /etc/pam.d/sudo && \
    echo "auth sufficient pam_permit.so" >> /etc/pam.d/sudo

# Set working directory
WORKDIR /workspace

# Create logs directory and set permissions
RUN mkdir -p /workspace/.devcontainer/logs && \
    mkdir -p /dc/shellhistory && \
    chown -R vscode:vscode /workspace && \
    chown -R vscode:vscode /dc/shellhistory && \
    chmod 755 /dc/shellhistory

# Set environment variables
ENV SHELL=/bin/bash \
    EDITOR="code --wait" \
    OPENSSL_CONF=/etc/ssl/openssl.cnf \
    PATH=/workspace/bin:$PATH

# Switch to non-root user
USER vscode 