# Deployment Guide

## Recommended topology

1. **App node** — SecureAssess API (`tsx` or compiled Node)
2. **Persistent volume** — `reports/` + `data/`
3. **Optional reverse proxy** — TLS termination (nginx/Caddy)
4. **Optional workers** (future) — queue-based scan runners

## Environment

| Variable | Purpose |
|----------|---------|
| `PORT` | Listen port (default 3847) |
| `SECUREASSESS_ENV` | Config profile name (`development`, `production`) |
| `NODE_ENV` | Fallback profile |

## Production checklist

- [ ] Bind behind VPN or SSO-protected network
- [ ] Persist `data/` and `reports/`
- [ ] Disable anonymous internet exposure
- [ ] Set logging to JSON
- [ ] Confirm `safety.requireAuthorization=true`
- [ ] Restrict OS permissions of the service account
- [ ] Monitor disk for report growth

## Process example

```bash
npm ci
npm run build
npm start
```

Use a process manager (systemd, PM2, container ENTRYPOINT).

## Docker (suggested)

```dockerfile
FROM mcr.microsoft.com/playwright:v1.51.0-jammy
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 3847
CMD ["npm", "start"]
```

Only deploy where authorized testing is contractually allowed.
