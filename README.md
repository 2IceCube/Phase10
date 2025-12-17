# Phase 10 – PHP/SQLite Web-App

Einfache, lokal lauffähige Web-Anwendung für Phase 10 mit HTML/PHP-Frontend und SQLite-Datenbank.

## Funktionen
- Nutzerkonten mit Rollen **Admin** und **Spieler**, anmeldegeschütztes Admin-Menü, Gastansicht möglich
- Punktesystem: 1 Punkt = 1 Cent Abzug vom hinterlegten Betrag, Einzahlungen pro Spieler hinterlegbar
- Verwaltung von 2–10 Spielern, Namensänderungen und Passwort-Updates über das Admin-Menü
- Phasenverwaltung (10 Phasen) mit frei editierbarer Info-Spalte, die alle Spieler sehen können
- Rundenerfassung, nachträgliches Bearbeiten/Löschen von Punkte-Einträgen, automatische Ermittlung des aktuellen Gewinners (höchster Restbetrag)

## Setup
1. PHP 8.1+ mit SQLite-Unterstützung bereitstellen.
2. Repository klonen und in das Verzeichnis wechseln.
3. Webserver starten, z. B. via PHP Built-in Server:
   ```bash
   php -S localhost:8000
   ```
4. Im Browser `http://localhost:8000` aufrufen.

Beim ersten Start wird automatisch eine SQLite-Datenbank unter `data/phase10.sqlite` angelegt. Der Standard-Admin lautet `admin` mit Passwort `admin123` (bitte im Admin-Menü ändern).

## Hinweise
- Dateien unter `data/` sind im `.gitignore` und sollten nicht eingecheckt werden.
- Die Anwendung ist für lokale/private Nutzung gedacht. Für produktiven Einsatz sollten weitere Sicherheitsmaßnahmen (TLS, CSRF-Schutz, Rate-Limits) ergänzt werden.
