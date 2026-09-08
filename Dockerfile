ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /src
COPY . .
RUN python scripts/build_dist.py --output /wheels

FROM ${PYTHON_IMAGE}
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 SIGMA_PROBE_OUTPUT_DIR=/reports
RUN groupadd --gid 10001 sigma \
    && useradd --uid 10001 --gid sigma --no-create-home sigma \
    && mkdir -p /reports /workspace \
    && chown sigma:sigma /reports /workspace
COPY --from=builder /wheels/*.whl /tmp/
RUN python -m pip install --no-index --no-deps /tmp/sigma_probe-*.whl \
    && rm /tmp/sigma_probe-*.whl
WORKDIR /workspace
USER 10001:10001
ENTRYPOINT ["sigma-probe"]
CMD ["--help"]
