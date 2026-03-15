# NeoConnect

NeoConnect is split into two independently deployable apps:

- `frontend/`: Next.js application for the staff-facing product
- `backend/`: Express + MongoDB API that handles auth, cases, polls, analytics, and file uploads

## Deploy structure

- `frontend/` can be deployed on Vercel or Render
- `backend/` can be deployed on Render
- The frontend talks to the backend through `NEXT_PUBLIC_API_URL`
- The backend allows the frontend origin through `FRONTEND_URL`

## Features covered

- Staff complaint/feedback form with:
  - category, department, location, severity
  - anonymous toggle
  - image/PDF upload
  - unique tracking ID in `NEO-YYYY-001` format
- Role-based access for:
  - Staff
  - Secretariat
  - Case Manager
  - Admin
- Case lifecycle:
  - New
  - Assigned
  - In Progress
  - Pending
  - Resolved
  - Escalated
- Secretariat inbox and assignment flow
- Case Manager updates, notes, and case closure
- Automatic 7-working-day escalation sweep with reminder note creation
- Public hub with:
  - announcements
  - quarterly digest
  - impact tracking
  - searchable minutes archive
- Polling with single-vote enforcement and charted results
- Analytics dashboard:
  - open cases by department
  - breakdowns by status/category/department
  - hotspot flagging for 5+ same-category cases in one department
- Admin user management and account activation toggles

## Setup

1. Install frontend dependencies:

```bash
cd frontend
npm install
```

2. Install backend dependencies:

```bash
cd ../backend
npm install
```

3. Create env files from:

- `frontend/.env.example`
- `backend/.env.example`

4. Start the backend:

```bash
cd backend
npm run dev
```

5. Start the frontend:

```bash
cd frontend
npm run dev
```

6. Open [http://localhost:3000](http://localhost:3000)

## Demo accounts

When the database is empty, the backend creates starter accounts automatically. All starter accounts use password `password123`.

- `staff@neoconnect.local`
- `secretariat@neoconnect.local`
- `manager@neoconnect.local`
- `admin@neoconnect.local`

## Notes

- Uploaded files are stored in `backend/uploads/`.
- The backend must know the deployed frontend URL through `FRONTEND_URL`.
- `FRONTEND_URL` can contain one URL or a comma-separated list if you want local development plus production, for example `https://your-frontend.vercel.app,http://localhost:3000`.
- The frontend must know the deployed backend URL through `NEXT_PUBLIC_API_URL`.
- Auth uses HTTP-only cookies, so frontend requests include credentials.

## Deployment

### Backend on Render

1. Create a new Web Service from the `backend/` folder.
2. Build command: `npm install && npm run build`
3. Start command: `npm run start`
4. Set env vars:
   - `PORT=4000`
   - `APP_URL=https://your-backend.onrender.com`
   - `FRONTEND_URL=https://your-frontend-domain`
   - `MONGODB_URI=...`
   - `MONGODB_DB=neoconnect`
   - `JWT_SECRET=...`

### Frontend on Vercel or Render

1. Deploy the `frontend/` folder as its own app.
2. Set `NEXT_PUBLIC_API_URL=https://your-backend.onrender.com`
3. Redeploy after env vars are saved.

## MongoDB setup

Option 1: local MongoDB

1. Install MongoDB Community Edition.
2. Start MongoDB so it listens on `127.0.0.1:27017`.
3. Set `MONGODB_URI=mongodb://127.0.0.1:27017/neoconnect` in `backend/.env`.

Option 2: MongoDB Atlas

1. Create a cluster in MongoDB Atlas.
2. Create a database user and allow your IP address.
3. Copy the connection string into `backend/.env` as `MONGODB_URI`.
4. Replace `<username>`, `<password>`, and the database name in the URI.
