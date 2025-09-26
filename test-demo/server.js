const fs = require("fs");
const https = require("https");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const fetch = require("node-fetch");
require("dotenv").config();

const {
  AUTH_URL,
  TOKEN_URL,
  USERINFO_URL,
  LOGOUT_URL,
  CLIENT_ID,
  SCOPE,
  REDIRECT_URI,
  PORT = 8080,
  USE_HTTPS = "true",
  TLS_KEY,
  TLS_CERT,
  SESSION_SECRET = "dev_secret"
} = process.env;

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { sameSite: "lax" }
  })
);

// Helpers
function base64url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomString(bytes = 64) { return base64url(crypto.randomBytes(bytes)); }
function sha256Base64Url(input) { const hash = crypto.createHash("sha256").update(input).digest(); return base64url(hash); }

// Step 1: Login
app.get("/login", (req, res) => {
  const state = randomString(16);
  const codeVerifier = randomString(64);
  const codeChallenge = sha256Base64Url(codeVerifier);

  req.session.pkce_state = state;
  req.session.pkce_verifier = codeVerifier;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  });

  res.redirect(`${AUTH_URL}?${params.toString()}`);
});

// Step 2+3: Callback → Token → UserInfo
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state || state !== req.session.pkce_state) {
    return res.status(400).send("Invalid state or missing code");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: req.session.pkce_verifier
  });

  try {
    const tokenResp = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    const tokenData = await tokenResp.json();

    const uiResp = await fetch(USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userinfo = await uiResp.json();

    const regCode = userinfo.aws_workspaces_regcode || "(not present)";

    res.send(`<h2>Login Success 🎉</h2><p><b>AWS WorkSpaces Reg Code:</b> ${regCode}</p><pre>${JSON.stringify(userinfo, null, 2)}</pre>`);
  } catch (e) {
    console.error("Error:", e);
    res.status(500).send("Token/UserInfo call failed");
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    const url = new URL(LOGOUT_URL);
    url.searchParams.set("client_id", CLIENT_ID);
    url.searchParams.set("post_logout_redirect_uri", `https://localhost:${PORT}/`);
    res.redirect(url.toString());
  });
});

// Start server
if (String(USE_HTTPS).toLowerCase() === "true") {
  const key = fs.readFileSync(TLS_KEY);
  const cert = fs.readFileSync(TLS_CERT);
  https.createServer({ key, cert }, app).listen(PORT, () => {
    console.log(`🔐 HTTPS server running at https://localhost:${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`HTTP server running at http://localhost:${PORT}`);
  });
}