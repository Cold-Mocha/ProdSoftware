ARG COURSE_PLATFORM=linux/amd64

FROM --platform=${COURSE_PLATFORM} ghcr.io/astral-sh/uv:latest AS uv

# Microsoft Python Dev Container image
FROM --platform=${COURSE_PLATFORM} mcr.microsoft.com/devcontainers/python:1-3.11-bullseye

# Install uv
COPY --from=uv /uv /uvx /bin/

# Install syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype (Software Vulnerability Scanner)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks (Secret Scanner)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

# Install Node.js (required for CodeQL JavaScript analysis and autobuild)
# Remove problematic yarn repository first to avoid GPG key errors
RUN rm -f /etc/apt/sources.list.d/yarn.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for CodeQL Go analysis / autobuild)
RUN curl -sSfL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install CodeQL CLI
RUN curl -sSfL https://github.com/github/codeql-cli-binaries/releases/download/v2.25.1/codeql-linux64.zip -o /tmp/codeql.zip \
    && unzip -q /tmp/codeql.zip -d /usr/local \
    && chmod +x /usr/local/codeql/codeql \
    && ln -s /usr/local/codeql/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.zip

# Pre-download CodeQL query packs for faster first run
# Using --github-auth-stdin to avoid issues with pack download, or use pack bundle as fallback
RUN codeql pack download codeql/python-queries \
    && codeql pack download codeql/javascript-queries \
    && codeql pack download codeql/java-queries \
    || echo "Note: Some query packs may not be available in offline mode. They will be downloaded on first use."

# Verify CodeQL, Grype, Node.js, and npm installation
RUN echo "CodeQL version:" && codeql version \
    && echo "Grype version:" && grype version \
    && echo "Gitleaks version:" && gitleaks version \
    && echo "Node.js version:" && node --version \
    && echo "npm version:" && npm --version \
    && echo "Go version:" && go version

# Set environment variables for uv
ENV UV_LINK_MODE=copy
ENV UV_COMPILE_BYTECODE=1
