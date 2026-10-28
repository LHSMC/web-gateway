
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

const GATEWAY_USER = process.env.GATEWAY_USER;
const GATEWAY_PASSWORD = process.env.GATEWAY_PASSWORD;

if (!GATEWAY_USER || !GATEWAY_PASSWORD) {
  console.error("Missing GATEWAY_USER or GATEWAY_PASSWORD.");
  process.exit(1);
}

function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

// Protect every route, including the frontend and API.
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");

  const header = req.headers.authorization || "";
  const match = header.match(/^Basic\s+(.+)$/i);

  if (match) {
    try {
      const decoded = Buffer.from(match[1], "base64").toString("utf8");
      const separator = decoded.indexOf(":");

      if (separator >= 0) {
        const user = decoded.slice(0, separator);
        const password = decoded.slice(separator + 1);

        if (
          safeEqual(user, GATEWAY_USER) &&
          safeEqual(password, GATEWAY_PASSWORD)
        ) {
          return next();
        }
      }
    } catch {
      // Invalid credentials are rejected below.
    }
  }

  res.set("WWW-Authenticate", 'Basic realm="Web Gateway"');
  return res.status(401).send("Sign-in required.");
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/check", rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
}), async (req, res) => {
  try {
    const input = req.query.url;

    if (!input || typeof input !== "string") {
      return res.status(400).json({ error: "Enter a URL." });
    }

    const url = new URL(
      input.includes("://") ? input : `https://${input}`
    );

    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    ) {
      return res.status(400).json({
        error: "Enter a valid HTTP or HTTPS URL."
      });
    }

    // Keep the test allowlist until destination security is implemented.
    const allowedHosts = new Set(
      (process.env.ALLOWED_HOSTS || "example.com")
        .split(",")
        .map(host => host.trim().toLowerCase())
        .filter(Boolean)
    );

    if (!allowedHosts.has(url.hostname.toLowerCase())) {
      return res.status(403).json({
        error: "This destination is not on the configured test allowlist."
      });
    }

    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(10000)
    });

    res.json({
      url: url.href,
      status: response.status,
      contentType: response.headers.get("content-type") || "unknown",
      message: "The server reached the test destination."
    });
  } catch (error) {
    res.status(502).json({
      error: "Could not reach that destination.",
      details: error.name === "TimeoutError"
        ? "Request timed out."
        : "Check the URL and server logs."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Web Gateway running on port ${PORT}`);
});
