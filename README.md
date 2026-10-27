# EditingZone.net — Online deployment

## Important
This ZIP intentionally does NOT include `.env` because it can contain private admin credentials. Set secrets in your hosting provider's Environment settings instead.

## Deploy to Render
1. Create a GitHub repository for this project and upload the contents of this folder. Do NOT upload `.env`.
2. Open https://dashboard.render.com/ and create **New → Web Service**.
3. Connect the GitHub repository.
4. Use:
   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
5. In Render's Environment settings, add:
   - `SESSION_SECRET` = a long random secret
   - `ADMIN_USERNAME` = choose a new admin username
   - `ADMIN_PASSWORD` = choose a new, unique admin password
   - `NAGAD_NUMBER` = your Nagad business number
6. Create the service and wait for the deploy to finish. Render will show the public `https://...onrender.com` URL.

## Important storage limitation
The current starter app stores orders in SQLite and uploads in a local `uploads/` folder. Render Free has an ephemeral filesystem, so local database records and uploaded files can disappear after restarts/redeploys/spin-down. This deployment is suitable for a demo only until persistent database/file storage is configured. Do not accept real customer payments or uploads yet.

## Google Drive
A Gmail address by itself cannot authorize uploads. Configure Google Drive API/OAuth environment variables (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`, `DRIVE_FOLDER_ID`) for the Google account that can write to the target folder.
