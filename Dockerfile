# syntax=docker/dockerfile:1

FROM python:3.11-slim

ARG TRIVY_VERSION=0.69.3

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tar \
    && curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xzf - -C /usr/local/bin trivy \
    && trivy --version \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY scanner/requirements.txt scanner/requirements.txt
RUN pip install --no-cache-dir -r scanner/requirements.txt

COPY scanner/ scanner/
COPY packages/ packages/

ENTRYPOINT ["python", "-m", "scanner.main"]
CMD ["--help"]
