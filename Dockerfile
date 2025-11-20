FROM python:3.11-slim

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service built with Litestar."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PYTHONUNBUFFERED=1

WORKDIR /httpbin

# Copy dependency files first for better caching
COPY Pipfile Pipfile.lock* setup.py /httpbin/
COPY httpbin/VERSION /httpbin/httpbin/

# Install dependencies
RUN pip install --no-cache-dir pip setuptools wheel && \
    pip install --no-cache-dir pipenv && \
    pipenv install --system --deploy --ignore-pipfile || \
    pip install --no-cache-dir litestar uvicorn[standard] brotli pydantic jinja2

# Copy application code
COPY . /httpbin

# Install the application
RUN pip install --no-cache-dir /httpbin

EXPOSE 80

CMD ["uvicorn", "httpbin:app", "--host", "0.0.0.0", "--port", "80"]
