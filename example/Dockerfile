FROM python:3-onbuild

RUN [ "python", "manage.py", "migrate" ]
RUN [ "python", "manage.py", "creatersakey" ]
EXPOSE 8000
CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]
