FROM python:3.11-slim
WORKDIR /app
COPY dashboard/requirements.txt .
RUN pip install -r requirements.txt
COPY dashboard/ .
EXPOSE 5000
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]