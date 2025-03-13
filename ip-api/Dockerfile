FROM python:3.9-slim

WORKDIR /app

COPY app.py /app/
COPY networks.txt /app/
COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

ENV ES_HOST=elasticsearch
ENV ES_PORT=9200
ENV ES_USER=""
ENV ES_PASS=""

EXPOSE 3131

CMD ["python", "app.py"]
