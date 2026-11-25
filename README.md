# innovAero Rallye

Handy-Seite für eine Rallye. Die Teams öffnen die Seite im Browser und entsperren sie mit dem Passwort, das sie beim Briefing bekommen. Am Passwort erkennt die Seite das Team. Danach führt die Seite Schritt für Schritt durch die Rallye. Alles geht per Antippen.

Die Seite ist eine einzelne statische Datei (`index.html`) und läuft auf GitHub Pages. Sie lädt nichts von Drittanbietern, auch die Schriften liegen im Repository.

## Verschlüsselung

- Der gesamte Inhalt (Stationen, Rätsel, Fragen, Zusatzaufgaben, Einstellungen) liegt nur verschlüsselt in `index.html`. Ohne Passwort ist er nicht lesbar, auch nicht im Quelltext.
- Ein zufälliger Inhaltsschlüssel verschlüsselt den Inhalt (AES-GCM). Für jedes Team ist dieser Schlüssel mit einem aus dem Team-Passwort abgeleiteten Schlüssel verpackt (PBKDF2, SHA-256). Füllwerte verbergen, wie viele Teams es gibt.
- Der Spielstand wird nur verschlüsselt im Browser gespeichert. Auf einem Handy muss das Passwort nur einmal eingegeben werden.
- Im Repository stehen weder Passwörter noch der Inhalt im Klartext.

## Inhalt bearbeiten

Der Inhalt liegt im Klartext in `content.json`. Diese Datei ist in `.gitignore` eingetragen und wird nicht hochgeladen. Nach jeder Änderung:

```bash
node tools/build.mjs a=PASSWORT_A b=PASSWORT_B
```

Das Skript verschlüsselt `content.json` und schreibt das Ergebnis in `index.html`. Danach `index.html` committen. Bleibt ein Passwort gleich, bleibt der Spielstand dieses Teams auf den Handys erhalten. Ein neues Passwort setzt ihn zurück.

## Schriften

Barlow Condensed und Public Sans, beide unter der SIL Open Font License 1.1 (siehe `fonts/`).
