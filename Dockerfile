
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git cmake ninja-build gcc g++ libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV OQS_INSTALL_PATH=/usr/local

RUN git clone --depth 1 --branch 0.16.0 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_BUILD_ONLY_LIB=ON \
       -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build --parallel 2 \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
