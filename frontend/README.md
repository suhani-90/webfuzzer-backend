## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`



When using the proxy, update `.env`:
```
VITE_API_URL=/api/v1
VITE_WS_URL=
```
And in `api.ts` update the WS line:
```typescript
const WS_BASE = import.meta.env.VITE_WS_URL || '';
// WebSocket URL becomes ws://localhost:5173/ws/... which Vite proxies to backend
```

