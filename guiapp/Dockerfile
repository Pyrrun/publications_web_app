FROM python:latest
ADD inter.py /
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
CMD [ "python", "./inter.py" ]