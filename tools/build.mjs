// Verschlüsselt content.json und schreibt das Ergebnis in index.html.
//
// Aufruf:  node tools/build.mjs a=PASSWORT_A b=PASSWORT_B
//
// content.json und die Passwörter gehören nicht ins Repository (content.json steht in .gitignore).
// Ablauf: Ein zufälliger Inhaltsschlüssel verschlüsselt den Inhalt (AES-GCM). Dieser Schlüssel wird
// für jedes Team mit einem aus dem Team-Passwort abgeleiteten Schlüssel (PBKDF2) verpackt.
// Bleibt ein Passwort gleich, wird das Salz des Teams übernommen. Dann bleibt der gespeicherte
// Spielstand auf den Handys gültig, auch wenn sich der Inhalt ändert.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ITER = 600000;
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const htmlPath = join(root, "index.html");
const contentPath = join(root, "content.json");
const OPEN = '<script type="application/json" id="vault">';
const CLOSE = "</script>";

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const b64 = (u) => Buffer.from(u).toString("base64");
const unb64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const norm = (pw) => pw.trim().toLowerCase();

async function teamKey(pw, salt, iter) {
  const base = await subtle.importKey("raw", enc.encode(norm(pw)), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(key, bytes) {
  const iv = rnd(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

const pw = Object.fromEntries(process.argv.slice(2).map((a) => {
  const i = a.indexOf("=");
  return i > 0 ? [a.slice(0, i), a.slice(i + 1)] : [a, ""];
}));

const content = JSON.parse(readFileSync(contentPath, "utf8"));
const teams = content.teams;
if (!teams || !Object.keys(teams).length) throw new Error("content.json braucht \"teams\".");
for (const id of Object.keys(teams)) {
  if (!pw[id] || !norm(pw[id])) {
    console.error("Aufruf: node tools/build.mjs " + Object.keys(teams).map((t) => t + "=PASSWORT").join(" "));
    process.exit(1);
  }
}
for (const id of Object.keys(pw)) if (!teams[id]) throw new Error("Unbekanntes Team: " + id);

const html = readFileSync(htmlPath, "utf8");
const a = html.indexOf(OPEN);
const b = html.indexOf(CLOSE, a);
if (a < 0 || b < 0) throw new Error("Platzhalter für den Tresor in index.html nicht gefunden.");
let old = null;
try { old = JSON.parse(html.slice(a + OPEN.length, b)); } catch {}

const cek = rnd(32);
const cekKey = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
const vault = { v: 1, iter: ITER, teams: {}, content: await seal(cekKey, enc.encode(JSON.stringify(content))) };

for (const [id, label] of Object.entries(teams)) {
  let salt = rnd(16), kept = false;
  const prev = old && old.iter === ITER && old.teams && old.teams[id];
  if (prev) {
    try {
      const k = await teamKey(pw[id], unb64(prev.salt), ITER);
      await subtle.decrypt({ name: "AES-GCM", iv: unb64(prev.iv) }, k, unb64(prev.wrapped));
      salt = unb64(prev.salt); kept = true;
    } catch {}
  }
  const k = await teamKey(pw[id], salt, ITER);
  const w = await seal(k, cek);
  vault.teams[id] = { label, salt: b64(salt), iv: w.iv, wrapped: w.ct };
  console.log(label + ": " + (kept ? "Passwort unverändert, Spielstände bleiben gültig" : "neues Passwort, Spielstände dieses Teams beginnen neu"));
}

writeFileSync(htmlPath, html.slice(0, a + OPEN.length) + "\n" + JSON.stringify(vault) + "\n" + html.slice(b));
console.log("index.html aktualisiert.");
