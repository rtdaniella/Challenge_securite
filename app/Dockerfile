FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt --no-cache-dir

EXPOSE 8501

CMD ["streamlit",  "run", "app.py", "--server.port=8501"]