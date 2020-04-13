FROM python:3.7-alpine
RUN apk add --no-cache gcc musl-dev linux-headers
WORKDIR /var/www
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
COPY requirements.txt requirements.txt
COPY .env .env
RUN pip install -r requirements.txt
EXPOSE 5000
COPY app.py app.py
CMD ["flask", "run"]