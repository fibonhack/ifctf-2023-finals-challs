# start by pulling the python image
FROM python@sha256:13927a8172d13b6cdc87f50bf0a38ff4eceef05262f83870c9f6474d16117687

# copy the requirements file into the image
COPY ./requirements.txt /app/requirements.txt

# switch working directory
WORKDIR /app

# install the dependencies and packages in the requirements file
RUN pip install -r requirements.txt

# copy every content from the local file to the image
COPY . /app

EXPOSE 8080

# configure the container to run in an executed manner
# ENTRYPOINT [ "python", "app.py"]
ENTRYPOINT [ "uwsgi", "wsgi.ini" ]