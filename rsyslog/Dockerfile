FROM python:3.12-slim
WORKDIR /app
COPY rsyslog/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/streams.py ./streams.py
COPY rsyslog/syslog_receiver.py .
EXPOSE 514/udp 514/tcp 12201/udp 5140/tcp
CMD ["python", "-u", "syslog_receiver.py"]
