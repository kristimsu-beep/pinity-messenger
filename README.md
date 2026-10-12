# Pinity Messenger

A Discord-inspired community and messaging app built with FastAPI, MongoDB, WebSockets, and a custom dark UI.

## Current foundation

- Account registration and login with hashed passwords and signed sessions
- MongoDB persistence for users, contacts, messages, and Pinity AI history
- Built-in Pinity AI contact created at registration
- Groq chat endpoint
- Cloudflare Workers AI image generation endpoint
- Profile customization, user search, and live message delivery over WebSockets
- Responsive desktop/mobile UI
- Render deployment blueprint

## Deploy to Render

1. Create a new **Web Service** and connect this repository.
2. Render can use `render.yaml`; review the environment variables before deploying.
3. Set `MONGODB_URI` to your MongoDB Atlas connection string and allow Render's outbound access in Atlas Network Access. Never commit the URI.
4. Set `GROQ_API_KEY` and Cloudflare account/token variables to enable AI features.
5. Deploy and test `/health`, then register an account.

The app uses `MONGODB_DATABASE=pinity_db` by default. `SESSION_SECRET` must remain private; the Render blueprint generates it.

## API

- `GET /health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/contacts`
- `GET /api/users/search?q=...`
- `GET /api/messages?conversation_id=...`
- `POST /api/messages`
- `POST /api/ai/chat`
- `POST /api/ai/image`
- `WS /ws?token=...&conversation_id=...`

## Development roadmap

Community/server channels and permissions, group DMs, file uploads, richer profile decorations, moderation, bot developer APIs, and WebRTC voice/video rooms are planned as separate follow-up modules. Do not expose API keys in frontend JavaScript.
