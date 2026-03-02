# lab9-wi26

## Password Auth (app.py)

```bash
docker compose up
```

Uses `app.py` and `init.sql`. Visit http://localhost:8000 for the register/login page.

If you make changes to `init.sql`, stop compose and run:

```bash
docker compose down -v && docker compose up
```

## OIDC Auth (app_oidc.py)

Create a `.env` file with your OIDC credentials:

```
OIDC_CLIENT_ID=your_client_id
OIDC_CLIENT_SECRET=your_client_secret
OIDC_REDIRECT_URI=http://localhost:8000/callback
```

Then run:

```bash
docker compose -f docker-compose.oidc.yml up
```

Uses `app_oidc.py` and `init_oidc.sql`. Visit http://localhost:8000 and click "Login with OIDC".

If you make changes to `init_oidc.sql`, stop compose and run:

```bash
docker compose -f docker-compose.oidc.yml down -v && docker compose -f docker-compose.oidc.yml up
```
