# Headless Chromium for the screenshot service.
#
# The base is Microsoft's Playwright image: Chromium and its system libraries
# come pinned with the matching Python package. Alpine (musl) is not an option
# for this, since Playwright's browser builds are glibc only. The tag must match
# the Playwright version in the image; pin the digest once it has been checked.
#
# This image is deliberately not the backend image: it has no XenoProxy code,
# no database driver and no secret. The process-creation guard of the backend
# cannot run here, because Chromium starts child processes by design.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app
COPY --chown=1000:1000 guard.py service.py ./

# The image's own unprivileged account; the container also runs with no
# capability and no-new-privileges from the compose file.
USER 1000:1000

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"]

ENTRYPOINT ["python", "/app/service.py"]
