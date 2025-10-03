FROM python:3.11-slim

WORKDIR /usr/src/app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN [ "python", "manage.py", "migrate" ]
RUN [ "python", "manage.py", "creatersakey" ]

# Create superuser with admin:admin credentials
ENV DJANGO_SUPERUSER_USERNAME=admin
ENV DJANGO_SUPERUSER_EMAIL=admin@example.com
ENV DJANGO_SUPERUSER_PASSWORD=admin
RUN [ "python", "manage.py", "createsuperuser", "--noinput" ]

EXPOSE 8000
CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]
