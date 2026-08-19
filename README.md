# ScamCheck Flask Web App

## Planned architecture

- Phone check → Azure SQL
- URL check → Google Safe Browsing
- Screenshot check → Azure Blob Storage → OpenAI API
- Authentication and scan history → Azure SQL
- Admin bulletins → Azure Blob Storage
- Container image → Azure Container Registry → Azure App Service

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Run in Docker

```bash
docker build -t scamcheck .
docker run --rm -p 8000:8000 scamcheck
```

Open `http://localhost:8000`.

## Recommended next build order

1. Flask-Login registration/login
2. Local SQLite models and role-based access
3. Phone-report CRUD
4. Google Safe Browsing
5. OpenAI screenshot analysis
6. Azure Blob Storage
7. Azure SQL
8. Docker → ACR → App Service
9. Managed Identity/RBAC
10. Azure Function for bulletin PDF processing
