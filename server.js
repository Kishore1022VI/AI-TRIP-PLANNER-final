import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

const app = express();
const PORT = 3000;

// Required for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());

const users = [
    { email: "admin@gmail.com", password: "1234" }
];

const SESSION_COOKIE_NAME = "atp_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const sessions = new Map(); // token -> { email, createdAt }

function parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;

    const parts = cookieHeader.split(";");
    for (const part of parts) {
        const [rawKey, ...rawValParts] = part.split("=");
        const key = (rawKey || "").trim();
        if (!key) continue;
        const rawVal = rawValParts.join("=");
        cookies[key] = decodeURIComponent((rawVal || "").trim());
    }
    return cookies;
}

app.use((req, _res, next) => {
    req.cookies = parseCookies(req.headers.cookie);
    next();
});

function getSession(req) {
    const token = req.cookies?.[SESSION_COOKIE_NAME];
    if (!token) return null;

    const session = sessions.get(token);
    if (!session) return null;

    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(token);
        return null;
    }

    return { token, ...session };
}

function requireAuth(req, res, next) {
    const session = getSession(req);
    if (!session) {
        const nextUrl = encodeURIComponent(req.originalUrl || "/trip");
        return res.redirect(`/login.html?next=${nextUrl}`);
    }
    req.user = session;
    next();
}

app.get("/check-auth", (req, res) => {
    const session = getSession(req);
    res.json({ loggedIn: Boolean(session), email: session?.email });
});

// Protected Trip Planner route (use this instead of /trip.html)
app.get("/trip", requireAuth, (_req, res) => {
    res.sendFile(path.join(__dirname, "public", "trip.html"));
});

// Prevent bypassing auth by hitting the static file directly
app.get("/trip.html", (_req, res) => {
    res.redirect(302, "/trip");
});

// LOGIN
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    const user = users.find(
        u => u.email === email && u.password === password
    );

    if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, { email: user.email, createdAt: Date.now() });

    const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
    res.setHeader(
        "Set-Cookie",
        `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}`
    );

    res.json({ message: "Login successful" });
});

// GENERATE ITINERARY
app.post("/generate-itinerary", (req, res) => {
    const { destination, travelDate, days, budget, interests } = req.body;

    let itinerary = [];

    for (let i = 1; i <= days; i++) {
        itinerary.push({
            day: i,
            morning: `Visit famous landmarks in ${destination}`,
            afternoon: `Enjoy ${interests.join(", ")}`,
            evening: `Explore local food spots`,
            cost: Math.floor(budget / days)
        });
    }

    res.json({
        destination,
        travelDate,
        days,
        itinerary
    });
});

// Serve static files after defining protected routes
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});