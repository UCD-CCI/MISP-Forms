FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    zbar-tools \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
#COPY .env /app/.env

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

EXPOSE 5000

ENV FLASK_ENV=production
ENV FLASK_APP=app.py

# can be changed to suit env
CMD ["gunicorn", "-w", "8", "-b", "0.0.0.0:5000", "app:app"]
