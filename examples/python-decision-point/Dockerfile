# Build context is the repository root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY sdk/python /opt/sdk/python
COPY examples/python-decision-point /opt/decision-point
RUN pip install "/opt/sdk/python[grpc]" \
    && pip install /opt/decision-point \
    && rm -rf /opt/sdk /opt/decision-point

USER 10001:10001
EXPOSE 8000 9091
ENTRYPOINT ["python", "-m", "decision_point_app.serve"]
CMD ["sdk"]
