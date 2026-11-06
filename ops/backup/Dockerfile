# The backup job: MongoDB's tools (from the mongo image) and rclone, for copies off-site
# (Amazon S3, Cloudflare R2, Backblaze B2 or any S3-compatible storage).
FROM mongo:7
RUN apt-get update \
 && apt-get install -y --no-install-recommends rclone ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY backup.sh /backup.sh
ENTRYPOINT ["bash", "/backup.sh"]
CMD ["loop"]
