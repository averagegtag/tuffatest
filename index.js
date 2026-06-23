const express = require("express");
const jwt = require("jsonwebtoken");
const { verifyChain, verifyNonceSig } = require("./verify");
const { decodeAttestationExtension } = require("./asn1");
const { isBanned } = require("./bans");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "change_this_in_production";
const APP_PACKAGE = process.env.APP_PACKAGE || "com.yourcompany.yourgame";
const APP_SHA256  = process.env.APP_SHA256  || "AA:BB:CC:..."; // your release keystore SHA256

const NONCE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const usedNonces = new Set(); // swap for Redis in production

app.post("/attest", async (req, res) => {
    const { nonce, nonceSig, certChain, manufacturer, model, fingerprint, sdkInt, deviceId } = req.body;

    // --- Editor passthrough (dev only, remove in production) ---
    if (process.env.NODE_ENV !== "production" && manufacturer === "unknown" && model === "editor") {
        const token = jwt.sign({ deviceId, status: "verified", editor: true }, JWT_SECRET, { expiresIn: "1h" });
        return res.json({ status: "verified", token });
    }

    try {
        // 1. Nonce freshness
        const nonceData = Buffer.from(nonce, "base64");
        if (usedNonces.has(nonce)) {
            return res.json({ status: "suspicious", reason: "replay_nonce" });
        }
        usedNonces.add(nonce);
        setTimeout(() => usedNonces.delete(nonce), NONCE_WINDOW_MS);

        // 2. Ban check
        if (await isBanned(deviceId)) {
            return res.json({ status: "banned", reason: "device_banned" });
        }

        // 3. Verify certificate chain signatures
        const chainValid = await verifyChain(certChain);
        if (!chainValid) {
            return res.json({ status: "compromised", reason: "invalid_cert_chain" });
        }

        // 4. Decode ASN.1 attestation extension from leaf cert
        const leafCertDer = Buffer.from(certChain[0], "base64");
        const attestation = decodeAttestationExtension(leafCertDer);

        if (!attestation) {
            return res.json({ status: "compromised", reason: "asn1_decode_failed" });
        }

        // 5. Check security properties
        if (attestation.rooted) {
            return res.json({ status: "compromised", reason: "device_rooted" });
        }
        if (!attestation.bootloaderLocked) {
            return res.json({ status: "compromised", reason: "bootloader_unlocked" });
        }
        if (attestation.verifiedBootState !== "verified") {
            return res.json({ status: "compromised", reason: "boot_state_unverified" });
        }

        // 6. Verify app package + signature
        if (attestation.packageName && attestation.packageName !== APP_PACKAGE) {
            return res.json({ status: "compromised", reason: "package_mismatch" });
        }
        if (attestation.appCertDigest && attestation.appCertDigest !== APP_SHA256) {
            return res.json({ status: "compromised", reason: "signature_mismatch" });
        }

        // 7. Verify nonce signature against leaf cert public key
        const sigValid = await verifyNonceSig(nonce, nonceSig, certChain[0]);
        if (!sigValid) {
            return res.json({ status: "compromised", reason: "nonce_sig_invalid" });
        }

        // 8. All passed — issue JWT
        const token = jwt.sign(
            { deviceId, model, manufacturer, status: "verified" },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        return res.json({ status: "verified", token });

    } catch (err) {
        console.error("[TuffATest]", err);
        return res.status(500).json({ status: "error", reason: "server_error" });
    }
});

app.listen(3000, () => console.log("[TuffATest] Listening on port 3000"));