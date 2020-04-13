FROM python:3.7-alpine
RUN apk update && apk add gcc libc-dev make git libffi-dev openssl-dev python3-dev libxml2-dev libxslt-dev
WORKDIR /var/www
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
COPY .env .env
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
EXPOSE 5000
COPY app.py app.py
COPY layout.html templates/layout.html
CMD ["flask", "run"]