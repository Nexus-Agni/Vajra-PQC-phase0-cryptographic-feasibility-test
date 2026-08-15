FROM python:3.14.6-slim

# Install dependencies for building OpenSSL
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Download and compile OpenSSL 3.5.7
WORKDIR /usr/src
RUN wget https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz && \
    tar -xzf openssl-3.5.7.tar.gz && \
    cd openssl-3.5.7 && \
    ./config --prefix=/opt/openssl-3.5.7 --openssldir=/opt/openssl-3.5.7/ssl -Wl,-rpath,/opt/openssl-3.5.7/lib64 && \
    make -j$(nproc) && \
    make install_sw && \
    cd .. && rm -rf openssl-3.5.7 openssl-3.5.7.tar.gz

# Rebuild python ssl module or use LD_LIBRARY_PATH? 
# Wait, if we use LD_LIBRARY_PATH, Python might load it if we prepend it.
# Actually, the OpenSSL 3 build installs to lib64 on some platforms.
# Let's ensure python uses it by setting LD_LIBRARY_PATH.
ENV LD_LIBRARY_PATH=/opt/openssl-3.5.7/lib64:/opt/openssl-3.5.7/lib:$LD_LIBRARY_PATH
ENV OPENSSL_CONF=/app/openssl/openssl.cnf
ENV PATH=/opt/openssl-3.5.7/bin:$PATH

# Verify OpenSSL version during image build
RUN openssl version && python -c "import ssl; print(ssl.OPENSSL_VERSION)"

ENV PYTHONPATH=/app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "src.main"]
