#!/bin/sh
set -eu
mkdir -p secrets
umask 077
for secret_name in api_token admin_token encryption_key; do
  secret_path="secrets/$secret_name"
  if [ ! -e "$secret_path" ]; then
    openssl rand -base64 32 > "$secret_path"
    echo "created $secret_path"
  else
    echo "kept existing $secret_path"
  fi
done
