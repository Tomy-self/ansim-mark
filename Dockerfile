FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scanner.py probe.py report.py report_html.py vibescan.py scan_worker.py server.py ./
ENV PYTHONUNBUFFERED=1
# Render는 PORT 환경변수를 넘겨줌
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
