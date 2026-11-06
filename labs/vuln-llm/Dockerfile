# vuln-llm — deliberately vulnerable LLM support agent (CMP-5006 wk 9-10).
# Stdlib-only, so the image is tiny and the whole app is auditable.
#
# Build:  docker build -t seclab/vuln-llm:local labs/vuln-llm
# Run  :  python -m seclab.targets --up vuln-llm     (preferred; localhost-only)
#
# On mac/win, host.docker.internal reaches a local Ollama automatically. On Linux,
# run with:  --add-host=host.docker.internal:host-gateway   (seclab.targets does
# not add this yet — see the lab README for the one-liner if you want the real
# model backend on Linux).
FROM python:3.12-slim

# No pip install: the app imports only the standard library. That is itself a
# small supply-chain lesson (week 8) — zero third-party dependencies, zero
# dependency-confusion surface.
WORKDIR /app
COPY app/vulnllm_app.py /app/vulnllm_app.py

# Non-root, because even a lab target should not model bad practice.
RUN useradd --create-home --uid 10001 appuser
USER appuser

ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["python", "/app/vulnllm_app.py"]
