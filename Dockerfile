FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/llmshield
COPY pyproject.toml README.md ./
COPY llmshield ./llmshield
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 llmshield
USER llmshield
EXPOSE 8000
CMD ["uvicorn", "llmshield.main:app", "--host", "0.0.0.0", "--port", "8000"]
