// Verschlüsselt content.json und schreibt das Ergebnis in index.html.
//
// Aufruf:  node tools/build.mjs airbus=PASSWORT boeing=PASSWORT
//          (ein Eintrag pro Team aus "teams" in content.json)
//
// content.json und die Passwörter gehören nicht ins Repository (content.json steht in .gitignore).
// Ablauf: Ein zufälliger Inhaltsschlüssel verschlüsselt den Inhalt (AES-GCM). Für jedes Team gibt es
// einen Eintrag, der mit dem aus seinem Passwort abgeleiteten Schlüssel (PBKDF2) verschlüsselt ist und
// das Team sowie den Inhaltsschlüssel enthält. Die Seite erkennt das Team allein am Passwort.
// Füllwerte in zufälliger Reihenfolge verbergen, wie viele Teams es gibt.
// Das Salz bleibt bei jedem Build gleich. Bleibt ein Passwort gleich, bleibt der Spielstand dieses Teams
// auf den Handys gültig, auch wenn sich der Inhalt ändert.

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

const content = JSON.parse(readFileSync(contentPath, "utf8"));
const teams = Object.keys(content.teams || {});
const usage = "Aufruf: node tools/build.mjs " + teams.map((t) => t + "=PASSWORT").join(" ");
if (!teams.length) throw new Error('content.json braucht "teams".');

const pw = Object.fromEntries(process.argv.slice(2).map((a) => {
  const i = a.indexOf("=");
  return i > 0 ? [a.slice(0, i), a.slice(i + 1)] : [a, ""];
}));
for (const id of teams) if (!pw[id] || !norm(pw[id])) { console.error(usage); process.exit(1); }
for (const id of Object.keys(pw)) if (!teams.includes(id)) { console.error("Unbekanntes Team: " + id + "\n" + usage); process.exit(1); }
if (new Set(teams.map((t) => norm(pw[t]))).size !== teams.length) { console.error("Jedes Team braucht ein eigenes Passwort."); process.exit(1); }
if (teams.length > SLOTS) throw new Error("Mehr als " + SLOTS + " Teams: SLOTS in tools/build.mjs erhöhen.");

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
const cek = rnd(32);
const cekKey = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);

const slots = [];
for (const id of teams) {
  const base = await subtle.importKey("raw", enc.encode(norm(pw[id])), "PBKDF2", false, ["deriveKey"]);
  const key = await subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  slots.push(await seal(key, enc.encode(JSON.stringify({ t: id, k: b64(cek) }))));
}
// Füllwerte mit gleicher Länge wie der längste echte Eintrag
const len = Math.max(...slots.map((s) => unb64(s.ct).length));
while (slots.length < SLOTS) slots.push({ iv: b64(rnd(12)), ct: b64(rnd(len)) });
for (let i = slots.length - 1; i > 0; i--) {
  const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
  [slots[i], slots[j]] = [slots[j], slots[i]];
}

const vault = { v: 2, iter: ITER, salt: b64(salt), slots, content: await seal(cekKey, enc.encode(JSON.stringify(content))) };
writeFileSync(htmlPath, html.slice(0, a + OPEN.length) + "\n" + JSON.stringify(vault) + "\n" + html.slice(b));
console.log("index.html aktualisiert (" + teams.length + " Teams).");
