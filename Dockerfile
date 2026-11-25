# Usage:
#   docker build -t nti .
#   docker run --rm -v "$PWD/cases:/data" nti /data/capture.pcap -o /data/reports
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLBACKEND=Agg
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY nti ./nti
COPY iocs ./iocs
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 1000 analyst

USER analyst
WORKDIR /data
ENTRYPOINT ["nti", "--intel-dir", "/app/iocs"]
CMD ["--help"]
