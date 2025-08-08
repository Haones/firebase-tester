FROM python:3.9-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt fb_tester.py .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "fb_tester.py"]
