FROM thehale/python-poetry

ADD . /app
WORKDIR /app
RUN poetry install

ENTRYPOINT ["poetry", "run", "python"]
CMD ["fancontrol/fancontrol.py"]
