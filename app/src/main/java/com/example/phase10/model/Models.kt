package com.example.phase10.model

data class Phase(
    val nummer: Int,
    val beschreibung: String,
    val info: String = ""
)

data class Spieler(
    val id: String,
    var name: String,
    var rolle: Rolle = Rolle.SPIELER,
    var einzahlungCent: Int = 0,
    var punkte: Int = 0,
    var aktuellePhase: Int = 1
) {
    val saldoCent: Int
        get() = einzahlungCent - punkte
}

enum class Rolle { ADMIN, SPIELER, GAST }

data class KontoStand(
    val spieler: Spieler,
    val differenzCent: Int
)

data class AdminZugang(
    var benutzername: String = "admin",
    var passwort: String = "phase10"
)

class PhaseRepository {
    private val phasen: MutableList<Phase> = MutableList(10) { index ->
        Phase(index + 1, "Phase ${index + 1}")
    }

    fun allePhasen(): List<Phase> = phasen

    fun updatePhase(index: Int, beschreibung: String, info: String) {
        if (index in phasen.indices) {
            phasen[index] = phasen[index].copy(beschreibung = beschreibung, info = info)
        }
    }
}

class SpielerRepository {
    private val spieler: MutableList<Spieler> = mutableListOf()

    init {
        repeat(2) { idx ->
            spieler.add(
                Spieler(
                    id = "spieler_$idx",
                    name = "Spieler ${idx + 1}",
                    rolle = if (idx == 0) Rolle.ADMIN else Rolle.SPIELER,
                    einzahlungCent = 1000
                )
            )
        }
    }

    fun alle(): List<Spieler> = spieler

    fun fuegeHinzu(neuer: Spieler) {
        if (spieler.size < 10) {
            spieler.add(neuer)
        }
    }

    fun updatePunkte(id: String, punkte: Int) {
        spieler.find { it.id == id }?.let { it.punkte = punkte }
    }

    fun updateEinzahlung(id: String, cent: Int) {
        spieler.find { it.id == id }?.let { it.einzahlungCent = cent }
    }

    fun updatePhase(id: String, phase: Int) {
        spieler.find { it.id == id }?.let { it.aktuellePhase = phase }
    }

    fun rename(id: String, neuerName: String) {
        spieler.find { it.id == id }?.let { it.name = neuerName }
    }

    fun kontoStand(): List<KontoStand> =
        spieler.sortedByDescending { it.saldoCent }.map { KontoStand(it, it.saldoCent) }
}
