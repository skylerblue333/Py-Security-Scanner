FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --create-home app
COPY src ./src
COPY main.py ./main.py
USER app
ENTRYPOINT ["python", "main.py"]
