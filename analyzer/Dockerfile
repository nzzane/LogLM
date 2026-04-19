FROM python:3.12-slim
WORKDIR /app
COPY analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/streams.py ./streams.py
COPY analyzer/ .
CMD ["python", "-u", "main.py"]
