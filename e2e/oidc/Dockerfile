FROM python:3.12-slim
RUN pip install --no-cache-dir pyjwt cryptography
COPY oidc.py /oidc.py
CMD ["python", "/oidc.py"]
