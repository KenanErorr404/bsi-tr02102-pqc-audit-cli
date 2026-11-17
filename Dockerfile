FROM python:3.12-alpine
LABEL org.opencontainers.image.title="BSI TR-02102 PQC, TR-03183-2 SBOM & NIS-2 Audit CLI" \
      org.opencontainers.image.description="Zero-dependency local & CI/CD crypto and CRA/SBOM compliance scanner (BSI TR-02102-1, TR-03183-2, TR-03185, NIS-2 § 30 BSIG)" \
      org.opencontainers.image.source="https://github.com/KenanErorr404/bsi-tr02102-pqc-audit-cli" \
      org.opencontainers.image.version="1.5.0" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /workspace
COPY bsi_pqc_check.py /usr/local/bin/bsi_pqc_check.py
RUN chmod +x /usr/local/bin/bsi_pqc_check.py

ENTRYPOINT ["python3", "/usr/local/bin/bsi_pqc_check.py"]
CMD ["--no-browser"]
