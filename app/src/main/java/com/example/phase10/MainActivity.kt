package com.example.phase10

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.example.phase10.model.AdminZugang
import com.example.phase10.model.PhaseRepository
import com.example.phase10.model.Rolle
import com.example.phase10.model.Spieler
import com.example.phase10.model.SpielerRepository
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            Phase10App()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Phase10App() {
    val spielerRepo = remember { SpielerRepository() }
    val phaseRepo = remember { PhaseRepository() }
    val adminZugang = remember { AdminZugang() }

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val (aktuellerUser, setUser) = remember { mutableStateOf<Spieler?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(text = "Phase 10 Verwaltung") })
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(12.dp)) {
            if (aktuellerUser == null) {
                LoginBereich(
                    spieler = spielerRepo.alle(),
                    adminZugang = adminZugang,
                    onLogin = { setUser(it) },
                    onGast = {
                        setUser(
                            Spieler(
                                id = "gast",
                                name = "Gast",
                                rolle = Rolle.GAST
                            )
                        )
                    },
                    onNeueSpieler = { spielerRepo.fuegeHinzu(it) },
                    onAdminDaten = { adminZugang.benutzername = it.first; adminZugang.passwort = it.second },
                    showMessage = { msg ->
                        scope.launch { snackbarHostState.showSnackbar(msg) }
                    }
                )
            } else {
                BenutzerOberflaeche(
                    user = aktuellerUser,
                    phaseRepo = phaseRepo,
                    spielerRepo = spielerRepo,
                    adminZugang = adminZugang,
                    onLogout = { setUser(null) }
                )
            }
        }
    }
}

@Composable
fun LoginBereich(
    spieler: List<Spieler>,
    adminZugang: AdminZugang,
    onLogin: (Spieler) -> Unit,
    onGast: () -> Unit,
    onNeueSpieler: (Spieler) -> Unit,
    onAdminDaten: (Pair<String, String>) -> Unit,
    showMessage: (String) -> Unit
) {
    val benutzername = remember { mutableStateOf("") }
    val passwort = remember { mutableStateOf("") }
    val neuerSpielerName = remember { mutableStateOf("") }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text = "Anmeldung", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(value = benutzername.value, onValueChange = { benutzername.value = it }, label = { Text("Benutzername") })
        OutlinedTextField(
            value = passwort.value,
            onValueChange = { passwort.value = it },
            label = { Text("Passwort") },
            visualTransformation = PasswordVisualTransformation()
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val adminLogin = benutzername.value == adminZugang.benutzername && passwort.value == adminZugang.passwort
                val spielerLogin = spieler.find { it.name == benutzername.value && it.rolle != Rolle.ADMIN }
                when {
                    adminLogin -> onLogin(spieler.first { it.rolle == Rolle.ADMIN })
                    spielerLogin != null -> onLogin(spielerLogin)
                    else -> showMessage("Zugangsdaten ungültig")
                }
            }) { Text("Login") }
            Button(onClick = onGast) { Text("Gast") }
        }

        OutlinedTextField(value = neuerSpielerName.value, onValueChange = { neuerSpielerName.value = it }, label = { Text("Neuer Spielername") })
        Button(onClick = {
            if (spieler.size < 10 && neuerSpielerName.value.isNotBlank()) {
                onNeueSpieler(
                    Spieler(
                        id = "spieler_${spieler.size}",
                        name = neuerSpielerName.value,
                        rolle = Rolle.SPIELER,
                        einzahlungCent = 0
                    )
                )
                showMessage("Spieler angelegt")
            } else {
                showMessage("Maximal 10 Spieler oder Name fehlt")
            }
        }) { Text("Spieler anlegen") }

        Text(text = "Admin Zugang ändern", style = MaterialTheme.typography.titleMedium)
        Button(onClick = {
            if (benutzername.value.isNotBlank() && passwort.value.isNotBlank()) {
                onAdminDaten(benutzername.value to passwort.value)
                showMessage("Admin Zugang aktualisiert")
            }
        }) { Text("Zugangsdaten setzen") }
    }
}

@Composable
fun BenutzerOberflaeche(
    user: Spieler,
    phaseRepo: PhaseRepository,
    spielerRepo: SpielerRepository,
    adminZugang: AdminZugang,
    onLogout: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
            Text(text = "Angemeldet als ${user.name} (${user.rolle})")
            Button(onClick = onLogout) { Text("Abmelden") }
        }
        Kartenbereich(user, spielerRepo)
        PhasenBereich(phaseRepo)
        if (user.rolle == Rolle.ADMIN) {
            AdminBereich(spielerRepo, phaseRepo)
        }
    }
}

@Composable
fun Kartenbereich(user: Spieler, spielerRepo: SpielerRepository) {
    val konto = remember { mutableStateOf(user.saldoCent) }
    konto.value = spielerRepo.alle().find { it.id == user.id }?.saldoCent ?: user.saldoCent

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "Eigener Stand")
            Text(text = "Punkte: ${user.punkte}")
            Text(text = "Phase: ${user.aktuellePhase}")
            Text(text = "Guthaben: ${konto.value} Cent")
        }
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "Aktuelle Rangliste")
            spielerRepo.kontoStand().forEach { stand ->
                Text("${stand.spieler.name}: ${stand.differenzCent} Cent")
            }
        }
    }
}

@Composable
fun PhasenBereich(phaseRepo: PhaseRepository) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "Phasen")
            phaseRepo.allePhasen().forEach { phase ->
                Text("Phase ${phase.nummer}: ${phase.beschreibung} – Info: ${phase.info}")
            }
        }
    }
}

@Composable
fun AdminBereich(spielerRepo: SpielerRepository, phaseRepo: PhaseRepository) {
    val punkte = remember { mutableStateOf("") }
    val einzahlung = remember { mutableStateOf("") }
    val phase = remember { mutableStateOf("") }
    val info = remember { mutableStateOf("") }
    val beschreibung = remember { mutableStateOf("") }
    val zielSpieler = remember { mutableStateOf(spielerRepo.alle().firstOrNull()?.id ?: "") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Admin Bereich")
            SpielerSelector(spielerRepo.alle(), zielSpieler.value) { zielSpieler.value = it }
            OutlinedTextField(value = punkte.value, onValueChange = { punkte.value = it }, label = { Text("Punkte setzen") })
            OutlinedTextField(value = einzahlung.value, onValueChange = { einzahlung.value = it }, label = { Text("Einzahlung (Cent)") })
            OutlinedTextField(value = phase.value, onValueChange = { phase.value = it }, label = { Text("Phase") })
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    punkte.value.toIntOrNull()?.let { spielerRepo.updatePunkte(zielSpieler.value, it) }
                    einzahlung.value.toIntOrNull()?.let { spielerRepo.updateEinzahlung(zielSpieler.value, it) }
                    phase.value.toIntOrNull()?.let { spielerRepo.updatePhase(zielSpieler.value, it) }
                }) { Text("Speichern") }
            }
        }
    }

    Spacer(modifier = Modifier.padding(vertical = 4.dp))

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Phasen anpassen")
            OutlinedTextField(value = phase.value, onValueChange = { phase.value = it }, label = { Text("Phase Nummer") })
            OutlinedTextField(value = beschreibung.value, onValueChange = { beschreibung.value = it }, label = { Text("Beschreibung") })
            OutlinedTextField(value = info.value, onValueChange = { info.value = it }, label = { Text("Info (sichtbar)") })
            Button(onClick = {
                val idx = phase.value.toIntOrNull()?.minus(1) ?: return@Button
                phaseRepo.updatePhase(idx, beschreibung.value.ifBlank { "Phase ${idx + 1}" }, info.value)
            }) { Text("Phase speichern") }
        }
    }
}

@Composable
fun SpielerSelector(spieler: List<Spieler>, ausgewaehlt: String, onChange: (String) -> Unit) {
    LazyColumn(modifier = Modifier.fillMaxWidth()) {
        items(spieler) { person ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(person.name)
                    Text("Rolle: ${person.rolle}")
                }
                Button(onClick = { onChange(person.id) }) {
                    Text(if (person.id == ausgewaehlt) "Ausgewählt" else "Wählen")
                }
            }
        }
    }
}
