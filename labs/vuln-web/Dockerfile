# vuln-web — small deliberately vulnerable web app (CMP-5006 week 6).
# Stdlib-only (http.server + sqlite3), so the image is tiny and the whole app is
# one auditable file.
#
# Build:  docker build -t seclab/vuln-web:local labs/vuln-web
# Run  :  python -m seclab.targets --up vuln-web    (localhost-only)
FROM python:3.12-slim

WORKDIR /app
COPY app/vulnweb_app.py /app/vulnweb_app.py

RUN useradd --create-home --uid 10001 appuser
USER appuser

ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["python", "/app/vulnweb_app.py"]
