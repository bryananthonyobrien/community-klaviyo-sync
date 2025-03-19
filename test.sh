docker run -it --rm --name debug-container \
  --env-file .env \
  community-klaviyo-sync sh -c "pytest unit_tests/ -s --log-cli-level=DEBUG"

