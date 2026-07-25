# Dashboard bv-secrets. Pure stdlib, aucune dépendance pip.
#
# L'image ne contient que la face LECTURE : le moteur et l'UI web. Le worker,
# seul composant privilégié, tourne hors conteneur (`bv-secrets install-service`).
FROM python:3.12-slim
WORKDIR /app

COPY bvsecrets/ /app/bvsecrets/
COPY web/ /app/web/
COPY secrets.conf /app/secrets.conf

# Chemins par défaut DANS le conteneur : le store est monté read-only, seul le
# spool est accessible en écriture — c'est la seule sortie du dashboard.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BV_SECRETS_CONF=/app/secrets.conf \
    BV_SECRETS_DIR=/opt/bv-secrets \
    BV_SPOOL=/spool \
    BV_ACCESS_CONF=/access/access.conf

USER 1000:1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["python", "-m", "web.server"]
