// Verschlüsselt content.json und schreibt das Ergebnis in index.html.
//
// Aufruf:  node tools/build.mjs PASSWORT
//
// content.json und das Passwort gehören nicht ins Repository (content.json steht in .gitignore).
// Ablauf: Ein zufälliger Inhaltsschlüssel verschlüsselt den Inhalt (AES-GCM). Dieser Schlüssel liegt
// in einem Eintrag, der mit dem aus dem Passwort abgeleiteten Schlüssel (PBKDF2) verschlüsselt ist.
// Füllwerte in zufälliger Reihenfolge lassen den echten Eintrag nicht erkennen.
// Das Salz bleibt bei jedem Build gleich. Bleibt das Passwort gleich, bleibt der Spielstand auf den
// Handys gültig, auch wenn sich der Inhalt ändert.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ITER = 600000;
const SLOTS = 8;
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

const pw = process.argv[2];
if (!pw || !norm(pw) || process.argv.length > 3) {
  console.error('Aufruf: node tools/build.mjs PASSWORT');
  process.exit(1);
}

const content = JSON.parse(readFileSync(contentPath, "utf8"));
const html = readFileSync(htmlPath, "utf8");
const a = html.indexOf(OPEN);
const b = html.indexOf(CLOSE, a);
if (a < 0 || b < 0) throw new Error("Platzhalter für den Tresor in index.html nicht gefunden.");
let old = null;
try { old = JSON.parse(html.slice(a + OPEN.length, b)); } catch {}

async function seal(key, bytes) {
  const iv = rnd(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

const salt = old && old.iter === ITER && old.salt ? unb64(old.salt) : rnd(16);
const base = await subtle.importKey("raw", enc.encode(norm(pw)), "PBKDF2", false, ["deriveKey"]);
const key = await subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const cek = rnd(32);
const cekKey = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);

const slots = [await seal(key, enc.encode(JSON.stringify({ t: "rallye", k: b64(cek) })))];
const len = unb64(slots[0].ct).length;
while (slots.length < SLOTS) slots.push({ iv: b64(rnd(12)), ct: b64(rnd(len)) });
for (let i = slots.length - 1; i > 0; i--) {
  const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
  [slots[i], slots[j]] = [slots[j], slots[i]];
}

const vault = { v: 2, iter: ITER, salt: b64(salt), slots, content: await seal(cekKey, enc.encode(JSON.stringify(content))) };
writeFileSync(htmlPath, html.slice(0, a + OPEN.length) + "\n" + JSON.stringify(vault) + "\n" + html.slice(b));
console.log("index.html aktualisiert.");
