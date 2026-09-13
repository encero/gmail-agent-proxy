# Gmail Agent Proxy

A deny-by-default Gmail API compatibility layer for a local agent. It can read mail and attachments, search, manage custom labels, and toggle only the `STARRED` and `IMPORTANT` system labels. Sending, drafting, trashing, archiving, marking read/unread, spam actions, forwarding, settings changes, and every unlisted mutation return `403` without being sent to Google.

## Trust boundary

Google requires the broad `gmail.modify` OAuth scope to apply labels to messages. The proxy's allowlist prevents use of that scope through its API, but a stolen decrypted refresh token could be used directly against Google. Keep the data volume, encryption key, admin token, and container host trusted. Email content is untrusted input to your agent and can contain prompt injection; the proxy controls mailbox permissions, not model behavior.

## Start

Prerequisites: Docker Compose and OpenSSL.

```sh
chmod +x scripts/generate-secrets.sh
./scripts/generate-secrets.sh
docker compose up --build -d
```

Every push to `main` is also built for `linux/amd64` and `linux/arm64` by GitHub Actions and published as `ghcr.io/OWNER/gmail-agent-proxy:latest`. Version tags such as `v1.2.3` additionally publish `1.2.3` and `1.2` image tags. Pull requests build and test the image without publishing it.

Open `http://127.0.0.1:3000/admin`, sign in with `secrets/admin_token`, and follow the page:

1. In a Google Cloud project, enable the Gmail API and configure the OAuth consent screen.
2. Create an OAuth 2.0 Web application client.
3. Add `http://127.0.0.1:3000/admin/oauth/callback` as an authorized redirect URI (or the exact `PUBLIC_BASE_URL` equivalent).
4. Upload the downloaded client JSON in the admin page, then link each personal or Workspace account.

Workspace administrators may need to approve the app or requested scope. For external apps in testing mode, add each account as a test user. Google may expire refresh tokens for consent screens left in testing mode.

## Connect Hermes

The Compose project creates a Docker network named `hermes-mail`. Attach the Hermes service to that external network:

```yaml
networks:
  hermes_mail:
    external: true
    name: hermes-mail
```

Inside that network the base URL is `http://gmail-agent-proxy:3000/gmail/v1`. Give Hermes the contents of `secrets/api_token` as a bearer token. Do not give it the admin token, encryption key, data volume, or Docker socket.

```sh
curl -H "Authorization: Bearer $(<secrets/api_token)" \
  http://127.0.0.1:3000/gmail/v1/accounts
```

Use an account ID/email in the Gmail `userId` path. `me` works only when exactly one account is linked.

## Safe API subset

- `GET /gmail/v1/accounts` (custom linked-account discovery)
- `GET /gmail/v1/accounts/-/messages` (custom cross-account search with an opaque aggregate page token)
- `GET /gmail/v1/users/{userId}/profile`
- `GET /gmail/v1/users/{userId}/messages`
- `GET /gmail/v1/users/{userId}/messages/{id}` (`minimal`, `metadata`, `full`, `raw`)
- `GET /gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}`
- `GET /gmail/v1/users/{userId}/threads` and `GET .../threads/{id}`
- `GET /gmail/v1/users/{userId}/labels` and `GET .../labels/{id}`
- `POST .../messages/{id}/modify`, `POST .../messages/batchModify`, and `POST .../threads/{id}/modify`, after label-policy validation
- Custom labels: create, patch, and delete. System label update/delete is blocked.

List query names and response bodies follow Gmail's documented forms. Aggregate search annotates each result with `accountId` and `accountEmail`; its page token is opaque and tracks independent Gmail cursors.

## Operations

Credentials and the uploaded OAuth client secret are AES-256-GCM encrypted in SQLite. The encryption key stays in a separate Compose secret. Metadata audit records contain endpoint templates, account IDs, resource IDs, result, and status—never queries, email bodies, or attachments—and are purged after 90 days by default.

Back up the Docker volume and `secrets/encryption_key` together. Losing the key makes stored credentials unrecoverable. Rotating the encryption key currently requires relinking accounts. Unlinking an account removes the proxy's stored token but does not revoke it at Google; revoke access in the Google Account security page when needed.

Run checks locally with:

```sh
npm install
npm run typecheck
npm test
```
