FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY client/ /app/
COPY start.py /app/start.py
USER 10001:10001
CMD ["python", "start.py"]
