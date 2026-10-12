FROM python:3.12-slim
RUN useradd -m app
WORKDIR /app
COPY --chown=app . .
USER app
# docker run --rm -v $PWD/out:/app/out vulnops --trivy scans/trivy.json --grype scans/grype.json --zap scans/zap.json -o out
ENTRYPOINT ["python", "-m", "vulnops.cli"]
CMD ["--trivy", "scans/trivy.json", "--grype", "scans/grype.json", "--zap", "scans/zap.json", "-o", "out", "--state", "out/state.json"]
