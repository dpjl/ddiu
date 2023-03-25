FROM python:3.9.16-slim

WORKDIR /app

COPY requirements.txt ./
RUN apt update \
        && apt -y install git \
        && pip install --no-cache-dir -r requirements.txt \
        && apt -y remove git \
        && apt -y clean

COPY ddiu.py .

CMD [ "python", "./ddiu.py"]