# Phase 10 – PHP/SQLite Web-App

Darkmode-Web-App für Phase 10 mit Registerkarten-Navigation, gebaut in HTML/PHP mit SQLite-Backend.

## Funktionen
- Nutzerkonten mit Rollen **Admin** und **Spieler**, anmeldegeschütztes Admin-Menü, Gastansicht via 4-stelligem Code
- Punktesystem: 1 Punkt = 1 Cent Abzug vom hinterlegten Betrag, Einzahlungen pro Spieler hinterlegbar
- Verwaltung von 2–10 Spielern, Namensänderungen und Passwort-Updates über das Admin-Menü, separater Spieler-Tab
- Phasenverwaltung (10 Phasen) mit frei editierbarer Info-Spalte, die alle Spieler/Gäste sehen können
- Rundenerfassung, nachträgliches Bearbeiten/Löschen von Punkte-Einträgen, automatische Ermittlung des aktuellen Gewinners (höchster Restbetrag)
- Modernes Darkmode-Design mit weichen Karten, responsiver Grid-Darstellung und sanften Tab-Wechseln (JS)

## Setup
1. PHP 8.1+ mit SQLite-Unterstützung bereitstellen.
2. Repository klonen und in das Verzeichnis wechseln.
3. Webserver starten, z. B. via PHP Built-in Server:
   ```bash
   php -S localhost:8000
   ```
4. Im Browser `http://localhost:8000` aufrufen.

Beim ersten Start wird automatisch eine SQLite-Datenbank unter `data/phase10.sqlite` angelegt. Der Standard-Admin lautet `admin` mit Passwort `admin123` (bitte im Admin-Menü ändern).

**Gastcode:** Der initiale Gastcode lautet `1234` und kann im Admin-Tab „Einzahlungen & Gastcode“ auf einen beliebigen 4-stelligen Zahlencode geändert werden. Gäste gelangen nur mit diesem Code in die Gastansicht.

**Hinweis zu nginx/PHP-FPM:** Die App ist eine klassische Single-Entry-PHP-Seite und funktioniert hinter einem Standard-nginx-Setup (Document Root auf das Repo zeigen, `index.php` als Fallback via FastCGI an PHP-FPM durchreichen).

## Hinweise
- Dateien unter `data/` sind im `.gitignore` und sollten nicht eingecheckt werden.
- Die Anwendung ist für lokale/private Nutzung gedacht. Für produktiven Einsatz sollten weitere Sicherheitsmaßnahmen (TLS, CSRF-Schutz, Rate-Limits) ergänzt werden.
