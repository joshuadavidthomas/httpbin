FROM python:3.12-slim

LABEL name="httpbin"
LABEL version="1.0.0"
LABEL description="A simple HTTP service (FastAPI)"
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONUNBUFFERED=1

WORKDIR /httpbin

# Copy requirements and install dependencies
COPY requirements.txt /httpbin/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /httpbin/
RUN pip install --no-cache-dir /httpbin

EXPOSE 80

CMD ["uvicorn", "httpbin.core:app", "--host", "0.0.0.0", "--port", "80"]
