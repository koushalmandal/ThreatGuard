# MongoDB setup

1. Copy `server/.env.example` to `server/.env`.
2. Set `MONGODB_URI` in the local `server/.env` using the Atlas Drivers connection string.
3. Ensure the Atlas database user and Network Access settings allow the backend to connect.
4. Start both services from the repository root with `npm run dev`.
5. Check API and database readiness at `http://localhost:5000/api/health`.

Never commit `server/.env` or share its credentials. The repository ignores local environment files.
