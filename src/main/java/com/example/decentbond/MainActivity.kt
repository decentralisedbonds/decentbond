package com.example.decentbond

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewScreenSizes
import androidx.compose.ui.unit.dp
import com.example.decentbond.ui.theme.DeCentBondTheme
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.security.KeyPair
import java.util.Base64
import kotlinx.serialization.json.Json
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Paint
import android.net.Uri
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import com.google.zxing.integration.android.IntentIntegrator
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.gestures.scrollable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.first
import org.json.JSONArray
import java.io.File
import java.io.IOException
import androidx.compose.material3.ExposedDropdownMenuBox
import java.text.NumberFormat
import java.util.Locale
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.AttachMoney
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import kotlinx.coroutines.delay
import java.security.SecureRandom
import java.security.Signature
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import kotlin.collections.plus
import kotlin.math.cos
import kotlin.math.sin
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.window.DialogProperties
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.FileInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import javax.net.ssl.*

var keyPair =  mutableStateOf<KeyPair?>(null)
var status = mutableStateOf("")
var serverIp = mutableStateOf("")
val formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm")





class MainActivity : ComponentActivity() {

    companion object {
        init { System.loadLibrary("native-lib") }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContent {
            DeCentBondTheme { DeCentBondApp() }
        }
    }


    override fun onDestroy() {
        super.onDestroy()
        //Log.d("HTTPServer", "Server stopped")
        //stopService(Intent(this, BondSyncService::class.java))
    }
}

@Composable
fun rememberGdprAcceptedState(context: Context): MutableState<Boolean> {
    val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
    return remember { mutableStateOf(prefs.getBoolean("gdpr_accepted", false)) }
}

@Composable
fun GdprDialog(
    prefs: SharedPreferences,
    onAccepted: () -> Unit
) {
    // Local state for the editable fields
    var name by remember { mutableStateOf("") }
    var contact by remember { mutableStateOf("") }
    var checked by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current

    val showError = remember { mutableStateOf(false) }
    // The dialog itself
    AlertDialog(
        onDismissRequest = { /* do nothing – prevent accidental dismiss */ },
        title = { Text(text = "GDPR Consent") },
        text = {
            Column(
                modifier = Modifier.padding(8.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // Name field
                Text(
                    text = "Due to the nature of the decentralised system all information is made public. The server however falls under GDPR and as such an agreement is required from the user for the processing and sharing of their data. \n \n Username and Information fields on the Profile page will be public information and will be shared with anyone that requests it. Created bonds including public keys, timedate, amount, currency are also considered public and shared with anyone that requests them, in addition to the receiver keeping a local copy. \n \n GDPR consent can be withdrawn at any time in the settings screen however due to the nature of the system anyone who has requested copies of the information during the window of consent may possess local copies of shared information. As such any information may be kept indefinitely by third parties without ways to remove it. \n \n Revoking GDPR consent solely informs the server to avoid sharing information. \n \n A good way to think about it is consider anything done with this app is public and irreversable. \n \n Username and Information can be modified at any time in the Profile page. Bonds are created as cryptographic signed objects and cannot be modified after creation. \n \n Revoking consent can be achieved by (modifying the server IP address to the consented server, pressing the 'revoke GDPR agreement' button in settings. \n \n If you have modified the server on the settings page, each server may save and process information differently so check with their specific terms before accepting. \n \n  If you wish to proceed and enter into this agreement enter name, contact details (this information is kept private and kept for GDPR reporting), give confirmative consent by checking the box and click confirm.",
                    modifier = Modifier.padding(start = 4.dp)
                )
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))

                // Contact field
                OutlinedTextField(
                    value = contact,
                    onValueChange = { contact = it },
                    label = { Text("Contact details (mobile number or email address)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))

                // Accept checkbox
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = checked,
                        onCheckedChange = { checked = it }
                    )
                    Text(
                        text = "I accept the GDPR terms",
                        modifier = Modifier.padding(start = 4.dp)
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    coroutineScope.launch {
                        if (gdprAccepted(name,ZonedDateTime.now(ZoneId.systemDefault()).format(formatter),contact)) {
                            prefs.edit()
                                .putBoolean("gdpr_accepted", true)
                                .apply()

                            // Notify the parent
                            onAccepted()
                        }else {
                            // Show the error popup
                            showError.value = true
                        }
                    }
                },
                enabled = checked && name != "" && contact != ""// only enable when the user checks the box
            ) {
                Text("Confirm")
            }
        },
        dismissButton = {
            // The close button simply dismisses the dialog without
            // persisting the acceptance flag – the dialog will re‑appear
            // on the next launch.
            TextButton(onClick = { onAccepted()}) {
                Text("Close")
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false
        )
    )

    // ------------------------------------------------------------------
    // Error popup that is shown only when `showError` is true
    // ------------------------------------------------------------------
    if (showError.value) {
        AlertDialog(
            onDismissRequest = { showError.value = false },
            title = { Text("Error") },
            text = {
                Text("Could not process GDPR agreement with server")
            },
            confirmButton = {
                Button(
                    onClick = { showError.value = false }
                ) {
                    Text("OK")
                }
            }
        )
    }
}

@SuppressLint("CoroutineCreationDuringComposition")
@PreviewScreenSizes
@Composable
fun DeCentBondApp() {
    var currentDestination by rememberSaveable { mutableStateOf(AppDestinations.USERS) }
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val activity = LocalContext.current as MainActivity

    val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
    val gdprAcceptedState = rememberGdprAcceptedState(context)

    if (!gdprAcceptedState.value && serverIp.value != "") {
        GdprDialog(
            prefs = prefs,
            onAccepted = { gdprAcceptedState.value = true }   // hide the dialog
        )
    }

    val storedProfile by UserProfileRepository.userProfileFlow(context)
        .collectAsState(initial = UserProfile())
    val nameInfoJson = JSONObject().apply {
        put("name", storedProfile.username)
        put("info", storedProfile.info)
    }
    /* Password dialog state */
    var showPasswordDialog by remember { mutableStateOf(true) }
    var dialogTitle by remember { mutableStateOf("Enter password") }
    var loading by remember { mutableStateOf(false) }

    /* Delete‑confirmation dialog state */
    var showDeleteDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val ipFile = File(context.filesDir,"ipFile")
        if(ipFile.exists()){
            serverIp.value = ipFile.readText()
        }
        if (KeyUtils.keyFileExists(context)) {
            dialogTitle = "Enter password to unlock key"
            showPasswordDialog = true
        } else {
            dialogTitle = "Create a new key – choose a password to encrypt the private key on this device - if this password is forgotten there is zero way to recover access"
            showPasswordDialog = true
        }
    }

    /* Password dialog handling */
    if(status.value=="Key loaded"){showPasswordDialog=false}
    PasswordDialog(
        visible = showPasswordDialog,
        title = dialogTitle,
        onDismiss = { showDeleteDialog = true },
        onPasswordEntered = { pwd ->
            // Immediately clear the password field so the IME can’t store it
            // (the dialog’s TextField should use `visualTransformation = PasswordVisualTransformation()`
            // and `keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)`).
            coroutineScope.launch {
                loading = true
                status.value = "Processing…"
                var success = false
                try {
                    if (KeyUtils.keyFileExists(context)) {
                        // Load existing key – the password is only used here and never kept
                        val kp = KeyUtils.loadKey(context, pwd)
                        if (kp == null) {
                            status.value = "Wrong password – try again"
                        } else {
                            keyPair.value = kp
                            status.value = "Key loaded"
                            success = true
                        }
                    } else {
                        // Create a brand‑new key pair
                        val kp = KeyUtils.generateRSAKeyPair()
                        // Save the key with the supplied password, then discard the password variable
                        KeyUtils.saveKey(context, pwd, kp)
                        keyPair.value = kp
                        status.value = "New key created & saved"
                        success = true

                        // Register the new key immediately
                        status.value = registerUser(storedProfile.username, storedProfile.info).toString()
                    }
                } finally {
                    // Reset UI state and wipe the password from memory
                    loading = false
                    if (success) showPasswordDialog = false
                    // Overwrite the password string so it isn’t retained in the IME cache
                    // (Kotlin strings are immutable, so we replace the reference with an empty one)
                    // The dialog’s TextField should also call `clearFocus()` after submission.
                    // Example:
                    // passwordState.value = ""
                    // focusManager.clearFocus()
                }
            }
        }

    )

    /* Delete‑confirmation dialog */
    DeleteConfirmationDialog(
        showDialog = showDeleteDialog,
        onDismiss = { showDeleteDialog = false },
        onConfirm = {
            KeyUtils.deleteKeyFile(context)
            dialogTitle = "Create a new key – choose a password"
            keyPair.value = null
            showPasswordDialog = true
        },
        "Resetting your private key will void all previous transactions on this device. Transactions are linked to your private key. Are you sure you want to delete it and create a new one?"
    )

    /* Navigation */
    NavigationSuiteScaffold(
        navigationSuiteItems = {
            AppDestinations.entries.forEach { dest ->
                item(
                    icon = { Icon(dest.icon, contentDescription = dest.label) },
                    label = { Text(dest.label) },
                    selected = dest == currentDestination,
                    onClick = { currentDestination = dest }
                )
            }
        }
    ) {
        Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
            when (currentDestination) {
                AppDestinations.USERS -> UsersScreen(name = "Android", modifier = Modifier.padding(innerPadding))
                AppDestinations.BONDS -> BondsScreen(modifier = Modifier.padding(innerPadding))
                AppDestinations.ANALYSIS -> AnalysisScreen(modifier = Modifier.padding(innerPadding))
                AppDestinations.NETWORK -> NetworkScreen(modifier = Modifier.padding(innerPadding))
                AppDestinations.PROFILE -> ProfileScreen(modifier = Modifier.padding(innerPadding))
                AppDestinations.SETTINGS -> settingsScreen(modifier = Modifier.padding(innerPadding))
            }
        }
    }
}

enum class AppDestinations(
    val label: String,
    val icon: ImageVector,
) {
    USERS("Users", Icons.Default.Person),
    BONDS("Bonds", Icons.Default.AttachMoney),
    ANALYSIS("Analysis", Icons.Default.AccountBalance),
    NETWORK("Network", Icons.Default.Cloud),
    PROFILE("Profile", Icons.Default.AccountBox),
    SETTINGS("Settings", Icons.Default.Build),

}



@Composable
fun TwoColumnBasic(
    leftContent: @Composable ColumnScope.() -> Unit,
    rightContent: @Composable ColumnScope.() -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        Column(
            modifier = Modifier
                .weight(1f)            // 50 % of the row
                .padding(end = 8.dp)
        ) {
            leftContent()
        }

        Column(
            modifier = Modifier
                .weight(1f)            // 50 % of the row
                .padding(start = 8.dp)
        ) {
            rightContent()
        }
    }
}

@Composable
fun DeleteConfirmationDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    text: String
) {
    var isButtonEnabled by remember { mutableStateOf(false) }
    var countdown by remember { mutableStateOf(5) }

    if (showDialog) {
        // Starting countdown when dialog is shown
        LaunchedEffect(showDialog) {
            isButtonEnabled = false
            countdown = 5

            while (countdown > 0) {
                delay(1000) // Delay for 1 second
                countdown--
            }
            isButtonEnabled = true // Enable button after countdown
        }

        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(text = "Delete Item") },
            text = {
                Column {
                    Text(text = text)
                    Spacer(modifier = Modifier.height(16.dp)) // Add space between text and timer
                    if (!isButtonEnabled) {
                        Text(text = "Please wait... $countdown seconds")
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onConfirm()
                        onDismiss()
                    },
                    enabled = isButtonEnabled // Enable button based on countdown
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text("Cancel")
                }
            }
        )
    }
}
@Composable
fun SimpleTextField(
    modifier: Modifier = Modifier,
    label: String = "Name",
    placeholder: String = "Enter your name",
    text: String,
    onTextChange: (String) -> Unit
) {
    TextField(
        value = text,
        onValueChange = onTextChange,
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp),
        label = { Text(label) },
        placeholder = { Text(placeholder) },
        singleLine = true
    )
}
// -----------------------------------------------------------------------------
// 5️⃣  Users screen (with persistence, delete & update)
// -----------------------------------------------------------------------------
@Composable
fun UsersScreen(name: String, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val activity = context as? ComponentActivity ?: return
    val coroutineScope = rememberCoroutineScope()

    // Load contacts from file on first composition
    var contacts: MutableList<Contact>
    contacts = loadContacts(context)


    /* Dialog state for the QR that we share */
    var showShareQr by remember { mutableStateOf(false) }

    /* Permission handling for camera */
    var cameraGranted by remember { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted -> cameraGranted = granted }

    var selectedContact by remember { mutableStateOf<Contact?>(null) }
    var showDeleteConfirmation by remember { mutableStateOf(false) }
    var contactToDelete by remember { mutableStateOf<Contact?>(null) }

    /* ZXing scanner */
    val scannerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val data = result.data
            val scanned = data?.getStringExtra("SCAN_RESULT") ?: ""
            if (scanned.isNotBlank() && contacts.none { it.publicKey == scanned }) {
                val newContact = Contact(scanned)

                coroutineScope.launch {
                    for(contact in contacts){
                        if(contact.publicKey==newContact.publicKey){
                            return@launch
                        }
                    }
                    newContact(context, scanned)
                }
            }
        }
    }

    Surface(modifier = modifier.fillMaxSize()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = {
                        if (!cameraGranted) {
                            permissionLauncher.launch(Manifest.permission.CAMERA)
                            val integrator = IntentIntegrator(activity)
                            integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                            integrator.setPrompt("Scan a public key")
                            integrator.setBeepEnabled(false)
                            scannerLauncher.launch(integrator.createScanIntent())
                        }
                        else{
                            val integrator = IntentIntegrator(activity)
                            integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                            integrator.setPrompt("Scan a public key")
                            integrator.setBeepEnabled(false)
                            scannerLauncher.launch(integrator.createScanIntent())
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Add contact") }

                Button(
                    onClick = { showShareQr = true },
                    modifier = Modifier.weight(1f)
                ) { Text("Share") }
            }

            Spacer(Modifier.height(12.dp))

            /* List of contacts */
            if (contacts.isNotEmpty()) {
                Text("Contacts:", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                LazyColumn {
                    items(contacts.size) { idx ->
                        var c = contacts[idx]
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedContact = c }
                        ) {
                            Text(
                                text = c.username ?: "Unknown username",
                                modifier = Modifier.padding(8.dp)
                            )
                            Divider()
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            Text(status.value, color = MaterialTheme.colorScheme.secondary)

            /* Share QR Dialog */
            if (showShareQr) {
                val publicKey = KeyUtils.getPublicKeyPemBase64Url()
                val bitmap = remember { generateQrBitmap(publicKey) }
                val bitmapPainter = remember { bitmap.asImageBitmap() }

                AlertDialog(
                    onDismissRequest = { showShareQr = false },
                    title = { Text("Public key QR") },
                    text = {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Image(
                                bitmap = bitmapPainter,
                                contentDescription = "Public key QR",
                                modifier = Modifier.size(250.dp)
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "Scan this QR code to add the public key to your contacts.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { showShareQr = false }) { Text("Close") }
                    }
                )
            }

            /* Contact info dialog (with Update & Delete) */

            selectedContact?.let { c ->
                var contact = c
                AlertDialog(
                    onDismissRequest = { selectedContact = null },
                    title = { Text(c.username ?: "Unknown") },
                    text = {
                        Column {
                            SelectionContainer {
                                Text(c.info ?: "No additional info")
                            }
                            Spacer(Modifier.height(12.dp))
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                modifier = Modifier.align(Alignment.End)
                            ) {
                                TextButton(onClick = {
                                    coroutineScope.launch {
                                        val updated = lookupContact(contact.publicKey)
                                        updated?.let {
                                            // Replace the old contact in the list
                                            val idx = contacts.indexOfFirst { it.publicKey == contact.publicKey }
                                            if (idx >= 0) contacts[idx] = it

                                            // Keep the dialog showing the updated data
                                            contact = it
                                            selectedContact = it
                                        }
                                        saveContacts(context, contacts)
                                    }
                                    selectedContact = null
                                }) { Text("Update") }

                                TextButton(onClick = {
                                    /* Confirm delete with a quick dialog */
                                    showDeleteConfirmation = true
                                    contactToDelete = c
                                }) { Text("Delete") }
                            }
                        }
                    },
                    confirmButton = {},
                    dismissButton = {}
                )
            }

            /* Confirmation dialog for deletion */
            if (showDeleteConfirmation && contactToDelete != null) {
                AlertDialog(
                    onDismissRequest = { showDeleteConfirmation = false },
                    title = { Text("Delete Item") },
                    text = { Text("Are you sure you want to delete ${contactToDelete!!.username ?: "this contact"}?") },
                    confirmButton = {
                        TextButton(onClick = {
                            contacts = contacts.filterNot { it.publicKey == contactToDelete!!.publicKey }.toMutableList()
                            saveContacts(context, contacts)
                            showDeleteConfirmation = false
                            selectedContact = null
                        }) { Text("Delete") }
                    },
                    dismissButton = {
                        TextButton(onClick = { showDeleteConfirmation = false }) { Text("Cancel") }
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BondsScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val locale = Locale.getDefault()

    val activity = LocalContext.current as MainActivity


    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    LaunchedEffect(Unit) {
        contacts = loadContacts(context)
    }

    val storedProfile by UserProfileRepository.userProfileFlow(context)
        .collectAsState(initial = UserProfile())

    /* ---- UI state ------------------------------------------------------- */
    var bonds by remember { mutableStateOf<List<Bond>>(emptyList()) }
    var showCreateDialog by remember { mutableStateOf(false) }

    /* ----- Currency filter state ---------------------------------------- */
    var selectedCurrency by remember { mutableStateOf<String?>(null) }

    /* ----- Selected bond (for the popup) --------------------------------- */
    var selectedBond by remember { mutableStateOf<Bond?>(null) }

    /* ---- Load bonds once on first composition --------------------------- */
    LaunchedEffect(Unit) {
        BondFetcher.fetchAndPersistBonds(context)
        bonds = loadBonds(context)
    }

    /* ---- Initialise default currency once bonds are loaded -------------- */
    LaunchedEffect(bonds) {
        if (bonds.isNotEmpty() && selectedCurrency == null) {
            selectedCurrency = NumberFormat.getCurrencyInstance(locale).currency.toString()
        }
    }

    /* ---- The main UI ----------------------------------------------------- */
    Surface(modifier = modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {

            /* 1️⃣  Create button */
            Button(
                onClick = { showCreateDialog = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Create Bond")
            }

            Spacer(Modifier.height(12.dp))

            Button(
                onClick = {
                    coroutineScope.launch {
                        BondFetcher.fetchAndPersistBonds(context)
                        bonds = loadBonds(context)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Update")
            }

            Spacer(Modifier.height(12.dp))

            /* 2️⃣  Currency filter drop‑down (only if we have bonds) */
            val availableCurrencies =
                bonds.map { it.currency }.distinct().sorted()

            if (availableCurrencies.isNotEmpty()) {
                CurrencyDropDown(
                    selectedCurrency = selectedCurrency ?: "",
                    currencies = availableCurrencies,
                    onCurrencySelected = { selectedCurrency = it }
                )

                Spacer(Modifier.height(12.dp))
            }

            /* 3️⃣  Balance row – sum of all bonds for the selected currency */
            val myPublicKey = KeyUtils.getPublicKeyPemBase64Url()
            val filteredBonds = bonds.filter { it.currency == selectedCurrency }.sortedByDescending { LocalDateTime.parse(it.timedate, formatter) }
            val balance = filteredBonds.fold(0L) { acc, bond ->
                val amt = bond.amount.toLong()
                val loaded = keyPair.value != null

                if (bond.receiver == bond.sender){
                    coroutineScope.launch{
                        if(loaded) {
                            deleteBond(context, bond)
                        }
                    }
                }
                if (bond.receiver == myPublicKey){
                    acc + amt
                } else if (bond.sender == myPublicKey) {
                    acc - amt
                } else {
                    coroutineScope.launch{
                        if(loaded) {
                            deleteBond(context, bond)
                        }
                    }
                    acc
                }
            }

            //val numberFormat = NumberFormat.getCurrencyInstance(Locale.getDefault())
            //val balanceStr = numberFormat.format(balance)

            Text(
                text = "Balance - " + selectedCurrency + ": " + balance,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(vertical = 8.dp)
            )

            /* 4️⃣  Bond list (filtered by the selected currency) */
            if (filteredBonds.isEmpty()) {
                Text("No bonds yet", style = MaterialTheme.typography.bodyLarge)
            } else {
                LazyColumn {
                    items(filteredBonds.size) { idx ->
                        val bond = filteredBonds[idx]

                        var sender: String = ""
                        var receiver: String = ""

                        for(contact in contacts){
                            if(contact.publicKey==bond.sender){
                                sender = contact.username.toString()
                            }
                        }
                        for(contact in contacts){
                            if(contact.publicKey==bond.receiver){
                                receiver = contact.username.toString()
                            }
                        }

                        if(bond.sender == myPublicKey) {
                            sender = storedProfile.username
                        }
                        if(bond.receiver == myPublicKey) {
                            receiver = storedProfile.username
                        }

                        BondRow(
                            bond,
                            myPublicKey = myPublicKey,
                            sender = sender,
                            receiver = receiver,
                            onClick = { selectedBond = bond }
                        )
                        Divider()
                    }
                }
            }

            /* 5️⃣  Create‑bond dialog --------------------------------------- */
            if (showCreateDialog) {
                BondCreateDialog(
                    context = context,
                    contacts = loadContacts(context),
                    onDismiss = { showCreateDialog = false },
                    onBondCreated = { newBond ->
                        bonds = bonds + newBond
                        showCreateDialog = false
                    }
                )
            }

            /* 6️⃣  Bond‑detail popup --------------------------------------- */
            selectedBond?.let { bond ->
                BondDetailDialog(
                    bond = bond,
                    myPublicKey = myPublicKey,
                    onDelete = {
                        coroutineScope.launch {
                            deleteBond(context, bond)
                            bonds = bonds.filterNot { it == bond }
                            selectedBond = null
                        }
                    },
                    onSendAgain = {
                        coroutineScope.launch {
                            createBond(bond.toJsonObject(),bond.receiver)
                        }
                    },
                    onDismiss = { selectedBond = null }
                )
            }
        }
    }
}

@Composable
fun CurrencyDropDown(
    selectedCurrency: String,
    currencies: List<String>,
    onCurrencySelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }

    Box(modifier = modifier) {
        // The read‑only text field that shows the current choice
        OutlinedTextField(
            value = selectedCurrency,
            onValueChange = {},
            readOnly = true,
            label = { Text("Currency") },
            trailingIcon = {
                Icon(
                    imageVector = Icons.Default.ArrowDropDown,
                    contentDescription = null,
                    modifier = Modifier
                        .clickable { expanded = !expanded }
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true }   // open on tap anywhere
        )

        // The menu itself
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier
                .fillMaxWidth()
        ) {
            currencies.forEach { cur ->
                DropdownMenuItem(
                    text = { Text(cur) },
                    onClick = {
                        onCurrencySelected(cur)
                        expanded = false
                    }
                )
            }
        }
    }
}

@Composable
private fun BondRow(bond: Bond, myPublicKey: String, sender: String, receiver: String, onClick: () -> Unit) {


    val amountDisplay = if (bond.receiver == myPublicKey)
        bond.amount.toLong()           // positive
    else
        -bond.amount.toLong()          // negative

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .clickable(onClick = onClick),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column (
            modifier = Modifier
                .horizontalScroll(rememberScrollState())
                .weight(0.8F)
        ){
            Text(bond.timedate + "  " + sender + " -> " + receiver, style = MaterialTheme.typography.bodyMedium)
        }
        Column(
            modifier = Modifier
                .weight(0.2F)
        ) {
            Text(
                amountDisplay.toString(),
                style = MaterialTheme.typography.bodyLarge,
                color = if (amountDisplay >= 0) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.error,
            )
        }

    }
}

@Composable
private fun BondDetailDialog(
    bond: Bond,
    myPublicKey: String,
    onDelete: () -> Unit,
    onSendAgain: () -> Unit,
    onDismiss: () -> Unit
) {
    /* Show a tiny confirmation dialog before actually deleting */
    var showDeleteConfirm by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    LaunchedEffect(Unit) {
        contacts = loadContacts(context)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Bond Details") },
        text = {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
            ) {
                Text("Amount: ${bond.amount}")
                Text("Currency: ${bond.currency}")
                Text("Date/Time: ${bond.timedate}")
                Spacer(Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            coroutineScope.launch {
                                for(contact in contacts){
                                    if(contact.publicKey==bond.sender){
                                        return@launch
                                    }
                                }
                                if(bond.sender == KeyUtils.getPublicKeyPemBase64Url()){
                                    return@launch
                                }
                                newContact(context,bond.sender)
                            }
                        }
                ){
                    Text("Sender   (click to add sender to contacts): ${bond.sender}", fontWeight = FontWeight.Bold)
                }
                Text("Receiver: ${bond.receiver}")
                Text("Nonce: ${bond.nonce}")
                Text("Checksum: ${bond.checksum}")
                Spacer(Modifier.height(16.dp))

                /* “Send Again” button – only if we own the bond */
                if (bond.sender == myPublicKey) {
                    Button(onClick = onSendAgain) {
                        Text("Send Again")
                    }
                    Spacer(Modifier.height(8.dp))
                }

                /* “Delete” button – opens the confirmation dialog */
                Button(
                    onClick = { showDeleteConfirm = true },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Delete")
                }

                /* Confirmation dialog for deletion */
                if (showDeleteConfirm) {
                    DeleteConfirmationDialog(
                        showDialog = true,

                        onDismiss = { showDeleteConfirm = false },
                        onConfirm = {
                            showDeleteConfirm = false
                            onDelete()
                            onDismiss()
                        },
                        "Delete bond from local device?"
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = {}
    )
}

/* -----------------------------------------------------------------------------
// 5.3  Helper – delete a bond file from disk
------------------------------------------------------------------------------ */
private suspend fun deleteBond(context: Context, bond: Bond) {
    withContext(Dispatchers.IO) {
        try {
            val file = File(bondsFolder(context), bond.nonce)
            if (file.exists()) file.delete()
        } catch (e: Exception) {
            Log.e("Bonds", "Failed to delete bond ${bond.nonce}", e)
        }
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BondCreateDialog(
    context: Context,
    contacts: List<Contact>,
    onDismiss: () -> Unit,
    onBondCreated: (Bond) -> Unit
) {
    val locale = Locale.getDefault()
    val numberFormat = NumberFormat.getCurrencyInstance(locale)
    var amountStr by remember { mutableStateOf("") }
    var currency by remember { mutableStateOf("") }
    var selectedReceiver by remember { mutableStateOf<Contact?>(null) }
    var errorMsg by remember { mutableStateOf("") }
    val coroutineScope = rememberCoroutineScope()
    currency = numberFormat.currency.toString()
    var inUse = false

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create Bond") },
        text = {
            Column {
                /* Amount – numeric field, only positive numbers allowed */
                TextField(
                    value = amountStr,
                    onValueChange = { amountStr = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Amount") },
                    placeholder = { Text("Positive number") },
                    singleLine = true,
                    isError = errorMsg.isNotEmpty()
                )

                /* Currency – free text (ISO‑4217) */
                TextField(
                    value = currency,
                    onValueChange = { currency = it },
                    label = { Text("Currency") },
                    placeholder = { Text("e.g. USD") },
                    singleLine = true
                )

                /* Receiver – drop‑down list of known contacts */
                ExposedDropdownMenuBox(
                    expanded = selectedReceiver == null,
                    onExpandedChange = { /* no-op, we close after selection */ }
                ) {
                    TextField(
                        readOnly = true,
                        value = selectedReceiver?.username ?: "",
                        onValueChange = {},
                        label = { Text("Receiver") },
                        trailingIcon = { Icon(Icons.Default.Person, contentDescription = null) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = selectedReceiver == null,
                        onDismissRequest = { /* handled by onExpandedChange */ }
                    ) {
                        contacts.forEach { c ->
                            DropdownMenuItem(
                                text = { Text(c.username ?: "Unknown") },
                                onClick = {
                                    selectedReceiver = c
                                }
                            )
                        }
                    }
                }

                /* Show any error (e.g. negative amount) */
                if (errorMsg.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(errorMsg, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if(!inUse) {
                        // --- Validation ------------------------------------------------
                        inUse = true
                        val amountUL = try {
                            amountStr.toULong()
                        } catch (_: Exception) {
                            errorMsg = "Amount must be a positive integer"
                            inUse = false
                            return@Button
                        }

                        if (amountUL == 0UL) {
                            errorMsg = "Amount must be > 0"
                            inUse = false
                            return@Button
                        }
                        if (currency.isBlank()) {
                            errorMsg = "Currency cannot be empty"
                            inUse = false
                            return@Button
                        }
                        if (selectedReceiver == null) {
                            errorMsg = "Please pick a receiver"
                            inUse = false
                            return@Button
                        }

                        // --- Build & upload bond --------------------------------------
                        coroutineScope.launch {
                            val newBond = try {
                                createBond(
                                    context = context,
                                    amount = amountUL,
                                    currency = currency,
                                    receiver = selectedReceiver!!.publicKey
                                )
                            } catch (e: Exception) {
                                errorMsg = "Failed to create bond – ${e.localizedMessage}"
                                inUse = false
                                null
                            }

                            if (newBond == null) {
                                errorMsg = "Failed to create bond – check logs"
                                inUse = false
                                return@launch
                            }

                            // Send the bond to the server
                            val posted = createBond( newBond.toJsonObject(), selectedReceiver!!.publicKey )

                            if (!posted) {
                                errorMsg = "Could not upload bond to server"
                                deleteBond(context, newBond)
                                inUse = false
                                return@launch
                            }

                            // Success – give the caller the Bond object
                            onBondCreated(newBond)
                            inUse = false
                        }
                    }
                }
            ) { Text("Create") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalysisScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleScope = (LocalContext.current as? ComponentActivity)?.lifecycleScope
        ?: rememberCoroutineScope()
    val coroutineScope = rememberCoroutineScope()

    var degreeText by remember { mutableStateOf("1") }
    var progress by remember { mutableStateOf(false) }
    var errorMsg by remember { mutableStateOf("") }

    // State that will hold the result after the analysis is finished
    var pagerankMap by remember { mutableStateOf<Map<String, Double>>(emptyMap()) }
    var edgeList by remember { mutableStateOf<List<BondEdge>>(emptyList()) }
    var contactMap by remember { mutableStateOf<Map<String, Contact>>(emptyMap()) }

    val appKey = remember { KeyUtils.getPublicKeyPemBase64Url() }

    val bonds = loadAnalysisBonds(context)
    edgeList = bonds.map { BondEdge(it.sender, it.receiver, it.amount.toLong()) }

    // 4️⃣  Compute PageRank
    pagerankMap = computePageRank(edgeList, damping = 0.85, iterations = 20)



    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Analysis",
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = degreeText,
            onValueChange = { degreeText = it.filter { ch -> ch.isDigit() } },
            label = { Text("Degrees of separation") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))

        Button(
            onClick = {

                coroutineScope.launch {
                    setAnalysisBonds(loadJsonBonds(context))
                }

                if (degreeText.isBlank() || degreeText.toIntOrNull() == null) {
                    errorMsg = "Please enter a valid integer (≥ 1)"
                    return@Button
                }
                val d = degreeText.toInt()
                if (d < 1) {
                    errorMsg = "Degree must be ≥ 1"
                    return@Button
                }

                deleteAnalysisBonds(context)

                // Reset state
                errorMsg = ""
                progress = true
                pagerankMap = emptyMap()
                edgeList = emptyList()
                contactMap = emptyMap()

                lifecycleScope.launch {
                    try {
                        // 1️⃣  Load contacts once – we need usernames for the graph
                        val contacts = loadContacts(context)
                        contactMap = contacts.associateBy { it.publicKey }

                        // 2️⃣  Crawl bonds
                        downloadAnalysisForDegrees(
                            degrees = d,
                            context = context,
                            appKey = appKey
                        )

                        // 3️⃣  Build graph
                        val bonds = loadAnalysisBonds(context)
                        edgeList = bonds.map { BondEdge(it.sender, it.receiver, it.amount.toLong()) }

                        // 4️⃣  Compute PageRank
                        pagerankMap = computePageRank(edgeList, damping = 0.85, iterations = 20)

                        // 5️⃣  Done!
                    } catch (e: Exception) {
                        errorMsg = e.localizedMessage ?: "Unknown error"
                    } finally {
                        progress = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) { Text("Start") }

        if (errorMsg.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(errorMsg, color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(16.dp))

        if (progress) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
        }

        // 6️⃣  Graph – only if we have something to show
        if (pagerankMap.isNotEmpty() && edgeList.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            AnalysisGraph(
                nodes = pagerankMap,
                edges = edgeList,
                contactMap = contactMap,
                appKey=appKey,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(400.dp)
                    .border(1.dp, MaterialTheme.colorScheme.outline)
            )
        }
    }
}

/**
 * 2️⃣  Recursively download all bonds up to the requested degree
 */


private suspend fun downloadAnalysisForDegrees(
    degrees: Int,
    context: Context,
    appKey: String
) {

    val analysisDir = File(context.filesDir, "analysis")
    analysisDir.mkdirs()
    val bondsDir = bondsFolder(context)
    bondsDir.listFiles()?.forEach { srcFile ->
        val dstFile = File(analysisDir, srcFile.name)
        srcFile.copyTo(dstFile, overwrite = true)
    }

    // 1️⃣  Get the list of known contacts once – we need them for degree 1
    val knownContacts = loadContacts(context).map { it.publicKey }

    // Helper to download bonds of a single key
    suspend fun downloadOf(key: String) = syncRemoteBondsToAnalysis(key, context)

    // 2️⃣  Degree 1 – all known contacts
    knownContacts.forEach { key ->
        downloadOf(key)
    }

    // 3️⃣  If more degrees, walk the graph
    var currentDegree = 2
    while (currentDegree <= degrees) {
        // Collect all keys that appear in the current set of bonds
        val bonds = loadAnalysisBonds(context)
        val pkSet = mutableSetOf<String>()
        bonds.forEach { bond ->
            pkSet += bond.sender
            pkSet += bond.receiver
        }
        // Remove duplicates, app key and the keys we already processed
        pkSet.remove(appKey)
        // Already processed keys are the ones we already downloaded (knownContacts + previous degrees)
        val alreadySeen = knownContacts.toMutableSet()
        for (d in 2 until currentDegree) {
            // Re‑compute the set for each intermediate degree
            // (we could store it, but for simplicity we recompute)
            val intermediateBonds = loadAnalysisBonds(context)
            intermediateBonds.forEach { b ->
                alreadySeen += b.sender
                alreadySeen += b.receiver
            }
        }
        pkSet.removeAll(alreadySeen)

        // Download each new key
        pkSet.forEach { key ->
            downloadOf(key)
        }

        currentDegree++
    }
}

/**
 * 3️⃣  Load bonds from the analysis folder
 */
private fun loadAnalysisBonds(context: Context): List<Bond> {
    // The folder that holds the downloaded bonds
    val folder = File(context.filesDir, "analysis")
    if (!folder.isDirectory) return emptyList()

    val bonds = mutableListOf<Bond>()

    folder.listFiles()?.forEach { file ->
        try {
            // ----- Read and parse the stored JSON -----
            val json = JSONObject(file.readText())

            // ----- Grab fields required for verification -----
            val nonce        = json.optString("nonce") ?: return@forEach
            val checksumB64  = json.optString("checksum") ?: return@forEach
            val senderKeyB64 = json.optString("sender") ?: return@forEach

            // ----- Re‑build the exact payload that was signed -----
            val payload = JSONObject().apply {
                put("amount",   json.getLong("amount"))
                put("currency", json.getString("currency"))
                put("timedate", json.getString("timedate"))
                put("sender",   json.getString("sender"))
                put("receiver", json.getString("receiver"))
                put("nonce",    json.getString("nonce"))
            }
            val payloadBytes = payload.toString().toByteArray(Charsets.UTF_8)
            val signatureBytes = Base64.getUrlDecoder().decode(checksumB64)

            // ----- Re‑construct the public key and verify -----
            val publicKey = KeyUtils.publicKeyFromBase64Url(senderKeyB64)
            val verified = KeyUtils.verifySignatureWithPublicKey(
                payloadBytes, signatureBytes, publicKey
            )
            if (!verified) {
                //Log.w("decentbond", "Signature check failed – bond $nonce discarded")
                return@forEach
            }

            // ----- Build the Bond object and add it to the list -----
            val bond = Bond(
                amount   = json.getLong("amount").toULong(),
                currency = json.getString("currency"),
                timedate = json.getString("timedate"),
                sender   = json.getString("sender"),
                receiver = json.getString("receiver"),
                nonce    = nonce,
                checksum = checksumB64
            )
            bonds += bond
        } catch (e: Exception) {
            // Skip malformed files – optionally log the error
            //Log.w("decentbond", "Skipping malformed bond file ${file.name}", e)
        }
    }

    return bonds
}

private fun deleteAnalysisBonds(context: Context){
    val folder = File(context.filesDir, "analysis")
    folder.listFiles()?.forEach { file ->
        file.delete()
    }
}

/**
 * 4️⃣  Page‑Rank implementation (simplified, no weights on out‑degree)
 */
private data class BondEdge(val from: String, val to: String, val amount: Long)

private fun computePageRank(
    edges: List<BondEdge>,
    damping: Double = 0.85,
    iterations: Int = 20
): Map<String, Double> {
    // Build adjacency and reverse adjacency
    val outWeights = mutableMapOf<String, Long>()
    val inNeighbors = mutableMapOf<String, MutableList<Pair<String, Long>>>()

    edges.forEach { e ->
        outWeights[e.from] = outWeights.getOrDefault(e.from, 0L) + e.amount
        inNeighbors.computeIfAbsent(e.to) { mutableListOf() }.add(e.from to e.amount)
    }

    // All unique nodes
    val nodes = (outWeights.keys + inNeighbors.keys).toSet()
    val n = nodes.size.toDouble()
    val baseRank = (1.0 - damping) / n

    var ranks = nodes.associateWith { baseRank }

    repeat(iterations) {
        val newRanks = mutableMapOf<String, Double>()
        nodes.forEach { node ->
            var sum = 0.0
            inNeighbors[node]?.forEach { (from, weight) ->
                val out = outWeights[from] ?: 1L
                sum += (weight.toDouble() / out.toDouble()) * ranks[from]!!
            }
            newRanks[node] = baseRank + damping * sum
        }
        ranks = newRanks
    }
    return ranks
}

/**
 * 5️⃣  Graph view – very simple Canvas drawing
 */
@Composable
private fun AnalysisGraph(
    nodes: Map<String, Double>,
    edges: List<BondEdge>,
    contactMap: Map<String, Contact>,
    appKey: String,
    modifier: Modifier = Modifier
) {
    /* ------------------------------------------------------------------ */
    /*  1️⃣ Persist names                                                 */
    /* ------------------------------------------------------------------ */
    val myName = contactMap[appKey]?.username ?: "You"
    val context = LocalContext.current

    /* ------------------------------------------------------------------ */
    /*  2️⃣ Layout – node positions (fixed “circle” layout)               */
    /* ------------------------------------------------------------------ */
    val nodeList = nodes.keys.toList()
    val radius = 120f
    val center = Offset(200f, 200f)
    val positions = nodeList.mapIndexed { i, _ ->
        val angle = i.toDouble() / nodeList.size * 2 * Math.PI
        Offset(
            (center.x + radius * cos(angle)).toFloat(),
            (center.y + radius * sin(angle)).toFloat()
        )
    }

    /* ------------------------------------------------------------------ */
    /*  3️⃣ Interaction state                                            */
    /* ------------------------------------------------------------------ */
    var scale by remember { mutableStateOf(1f) }
    var panOffset by remember { mutableStateOf(Offset.Zero) }

    /* ------------------------------------------------------------------ */
    /*  4️⃣ Pre‑compute balances (for the dialog)                        */
    /* ------------------------------------------------------------------ */
    val balanceMap: Map<String, Long> = edges.groupBy { it.to }
        .mapValues { (_, list) -> list.sumOf { it.amount } }

    /* ------------------------------------------------------------------ */
    /*  5️⃣ Selected node for dialog                                    */
    /* ------------------------------------------------------------------ */
    var selectedNodeKey by remember { mutableStateOf<String?>(null) }

    /* ------------------------------------------------------------------ */
    /*  6️⃣ Canvas – touch handling + drawing                            */
    /* ------------------------------------------------------------------ */
    Canvas(
        modifier = modifier
            .background(Color.White)
            /* 6.1  Handle gestures ------------------------------------------------ */
            .pointerInput(Unit) {
                //  • Drag → pan
                detectDragGestures { change, dragAmount ->
                    panOffset += dragAmount
                }

                //  • Pinch‑zoom
                detectTransformGestures { _, pan, zoom, _ ->
                    panOffset += pan
                    scale = (scale * zoom).coerceIn(0.2f, 5f)
                }

                //  • Double‑tap → reset scale & pan
                detectTapGestures(
                    onDoubleTap = {
                        scale = 1f
                        panOffset = Offset.Zero
                    }
                )

                //  • Tap → node detection (the meat of the fix)
                detectTapGestures { tapOffset ->
                    // Convert the tap position into the canvas coordinate system
                    // (i.e. undo pan & zoom).
                    val localTap = Offset(
                        (tapOffset.x - panOffset.x) / scale,
                        (tapOffset.y - panOffset.y) / scale
                    )

                    // Search for the closest node within the (scaled) radius
                    var nearest: Pair<Int, Float>? = null
                    nodeList.forEachIndexed { idx, pk ->
                        val nodePos = positions[idx]
                        val dist = (nodePos - localTap).getDistance()
                        val hitRadius = 40f * scale          // radius grows with zoom
                        if (dist <= hitRadius) {
                            if (nearest == null || dist < nearest.second) {
                                nearest = idx to dist
                            }
                        }
                    }
                    nearest?.let { selectedNodeKey = nodeList[it.first] }
                }
            }

            /* 6.2  Apply scale – use graphicsLayer so the Canvas itself is scaled  */
            .graphicsLayer { scaleX = scale; scaleY = scale }   // ← NEW
    ) {
        /* 6.3  Translate by the accumulated pan offset */
        translate(panOffset.x, panOffset.y) {
            /* 6.4  Draw edges */
            edges.forEach { edge ->
                val fromIdx = nodeList.indexOf(edge.from)
                val toIdx   = nodeList.indexOf(edge.to)
                if (fromIdx == -1 || toIdx == -1) return@forEach

                val fromPos = positions[fromIdx]
                val toPos   = positions[toIdx]
                val thickness =
                    (edge.amount.toDouble() / 1000.0).coerceIn(1.0, 5.0).toFloat()

                drawLine(
                    color = Color.Blue,
                    start = fromPos,
                    end = toPos,
                    strokeWidth = thickness,
                    cap = StrokeCap.Round
                )
            }

            /* 6.5  Draw nodes & labels */
            nodeList.forEachIndexed { i, pk ->
                val pos = positions[i]
                val rank = nodes[pk] ?: 0.0
                val size = 8f + 20f * rank.toFloat()
                val name = if (pk == appKey) myName
                else lookupUsername(pk,context)?:contactMap[pk]?.username ?: pk.substring(0, 8)

                drawCircle(
                    color = Color.Green,
                    radius = size,
                    center = pos
                )

                // Label below the node
                drawContext.canvas.nativeCanvas.apply {
                    drawText(
                        name,
                        pos.x,
                        pos.y + size + 12f,
                        Paint().apply {
                            color = android.graphics.Color.BLACK
                            textSize = 32f
                            isAntiAlias = true
                            textAlign = Paint.Align.CENTER
                        }
                    )
                }
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /*  7️⃣ Node balance dialog                                          */
    /* ------------------------------------------------------------------ */
    selectedNodeKey?.let { key ->
        val name = if (key == appKey) myName
        else contactMap[key]?.username ?: key.substring(0, 8)
        val balance = balanceMap[key] ?: 0L
        AlertDialog(
            onDismissRequest = { selectedNodeKey = null },
            title = { Text(name) },
            text = { Text("Balance: $balance") },
            confirmButton = {
                TextButton(onClick = { selectedNodeKey = null }) {
                    Text("OK")
                }
            }
        )
    }
}

@Composable
fun NetworkScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // 1️⃣  Load all analysis bonds
    val bonds by remember { mutableStateOf(loadAnalysisBonds(context)) }

    // 2️⃣  Compute a map of net balances
    val balanceMap by remember { mutableStateOf(computeBalancesForAnalysis(bonds)) }

    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    LaunchedEffect(Unit) {
        contacts = loadContacts(context)
    }

    // 3️⃣  Sort keys by descending balance
    val sortedKeys = balanceMap.entries
        .sortedByDescending { it.value }
        .map { it.key }

    // 4️⃣  Cache usernames that we already know
    val usernameCache = remember { mutableMapOf<String, String>() }

    // 5️⃣  State for the dialog (selected key)
    var selectedKey by remember { mutableStateOf<String?>(null) }

    Surface(modifier = modifier.fillMaxSize()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "Network – Public Keys & Balances",
                style = MaterialTheme.typography.headlineMedium
            )
            Spacer(Modifier.height(12.dp))

            if (sortedKeys.isEmpty()) {
                Text("No analysis bonds yet.", style = MaterialTheme.typography.bodyLarge)
            } else {
                LazyColumn {
                    items(sortedKeys.size) { idx ->
                        val pk = sortedKeys[idx]
                        val balance = balanceMap[pk] ?: 0L
                        var username = "";
                        username = lookupUsername(pk,context)?: ""
                        if (username == "") {
                            val usernameState = usernameForKey(pk, context, usernameCache)
                            username = usernameState.value ?: "username not found"
                        }

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedKey = pk }
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(username, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                if (balance >= 0) "+$balance" else balance.toString(),
                                color = if (balance >= 0) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyLarge
                            )
                        }
                        Divider()
                    }
                }
            }
        }
    }

    /* -------------------------------------------------------------
     *  Dialog – show all bonds linked to the selected key
     * ------------------------------------------------------------- */
    selectedKey?.let { pk ->
        // Filter bonds that involve this key
        val related = bonds.filter { it.sender == pk || it.receiver == pk }

        AlertDialog(
            onDismissRequest = { selectedKey = null },
            title = {
                // Resolve username for the dialog title
                val titleState = usernameForKey(pk, context, usernameCache)
                val title = titleState.value ?: pk.substring(0, 8)
                Text(title)
            },
            text = {
                if (related.isEmpty()) {
                    Text("No bonds for this key.")
                } else {
                    Column(
                        modifier = Modifier
                            .verticalScroll(rememberScrollState())
                            .heightIn(max = 400.dp)
                    ) {
                        related.forEach { bond ->
                            val otherSide = if (bond.sender == pk) bond.receiver else bond.sender
                            val otherNameState = usernameForKey(otherSide, context, usernameCache)
                            val otherName = otherNameState.value ?: otherSide.substring(0, 8)

                            Card(modifier = Modifier.padding(vertical = 4.dp)) {
                                Column(Modifier.padding(8.dp)) {
                                    Text(
                                        "Date: ${bond.timedate}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        "Currency: ${bond.currency}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        "Amount: ${bond.amount}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        if (bond.receiver == pk) "Received from $otherName"
                                        else "Sent to $otherName",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    coroutineScope.launch {
                        for(contact in contacts){
                            if(contact.publicKey==pk){
                                return@launch
                            }
                        }
                        if(pk == KeyUtils.getPublicKeyPemBase64Url()){
                            return@launch
                        }
                        newContact(context,pk)
                        selectedKey = null
                    }
                }) { Text("Add Contact") }

            },
            confirmButton = {
                TextButton(onClick = { selectedKey = null }) { Text("Close") }
            }
        )
    }
}

private fun computeBalancesForAnalysis(bonds: List<Bond>): Map<String, Long> {
    val balances = mutableMapOf<String, Long>()

    bonds.forEach { bond ->
        val amt = bond.amount.toLong()
        // receiver gains
        balances[bond.receiver] = balances.getOrDefault(bond.receiver, 0L) + amt
        // sender loses
        balances[bond.sender] = balances.getOrDefault(bond.sender, 0L) - amt
    }
    return balances
}

/**
 *  Return a username for a key, looking it up on the server if we don’t have it locally.
 *  The lookup is performed asynchronously – the caller must observe the returned state.
 */
@Composable
private fun usernameForKey(
    key: String,
    context: Context,
    cached: MutableMap<String, String>
): State<String?> {
    val state = remember(key) { mutableStateOf<String?>(cached[key]) }

    // If we already know it – no need to look it up
    if (state.value != null) return state

    // Look‑up the key on the server (this is a background job)
    LaunchedEffect(key) {
        val contact = lookupContact(key)          // uses the same helper that the Users screen uses
        val name = contact?.username ?: key.substring(0, 8)
        cached[key] = name
        state.value = name
    }
    return state
}

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter", "CoroutineCreationDuringComposition")
@Composable
fun settingsScreen(modifier: Modifier = Modifier) {
    val activity = LocalContext.current as MainActivity
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)

    // UI state
    var status by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }

    val ipFile = File(context.filesDir,"ipFile")

    val gdprAcceptedState = rememberGdprAcceptedState(context)
    var showDialog by remember { mutableStateOf(false) }

    if (!gdprAcceptedState.value && serverIp.value != "") {
        GdprDialog(
            prefs = prefs,
            onAccepted = { gdprAcceptedState.value = true }   // hide the dialog
        )
    }

    /* --------------------------------------------------------------------- */
    /*  Export launcher – ACTION_CREATE_DOCUMENT (zip)                      */
    /* --------------------------------------------------------------------- */
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/zip")
    ) { uri: Uri? ->
        uri?.let { chosenUri ->
            loading = true
            coroutineScope.launch {
                exportAllData(context, chosenUri, snackbarHostState)
                loading = false
            }
        }
    }
    val showDialog2 = remember { mutableStateOf(false) }

    // 1️⃣  Snackbar host state

    Scaffold(
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) {
                /* 2️⃣  The dialog (shown only when showDialog is true) */
        if (showDialog2.value) {
            AlertDialog(
                onDismissRequest = { showDialog2.value = false }, // user tapped outside or pressed back
                title = { Text("Confirm revocation") },
                text = {
                    Text(
                        """
                        Are you sure you want to revoke the GDPR agreement?
                        This action is irreversible.
                        """.trimIndent()
                    )
                },
                confirmButton = {
                    Button(onClick = {
                        showDialog2.value = false          // close the dialog

                        coroutineScope.launch {
                            val result = gdprDelete()   // actually revoke
                            result
                                if(gdprDelete()) { // ← success branch
                                    snackbarHostState.showSnackbar(
                                        "Consent successfully withdrawn."
                                    )
                                }
                                else{   // ← failure branch
                                    snackbarHostState.showSnackbar(
                                        """
                                        Failed to withdraw consent, please ensure correct server is entered and that you are connected to the internet.
                                        """.trimIndent()
                                    )
                                }
                        }
                    }) {
                        Text("Yes, revoke")
                    }
                },
                dismissButton = {
                    Button(onClick = { showDialog2.value = false }) {
                        Text("Cancel")
                    }
                }
            )
        }
    }

    Surface(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Column (
            modifier = Modifier
                .verticalScroll(rememberScrollState())
        ){
            /* Existing Server‑IP field … */
            Surface() {
                SimpleTextField(
                    label = "Server IP address",
                    placeholder = "Enter chosen server IP address",
                    text = serverIp.value,
                    onTextChange = {
                        serverIp.value = it
                        ipFile.writeText(it)
                    }
                )
            }
            Spacer(Modifier.height(24.dp))

            Text("Server may require GDPR agreement")

            Button(
                onClick = {
                    gdprAcceptedState.value = false
                    prefs.edit().putBoolean("gdpr_accepted", false).apply()},
                modifier = Modifier.fillMaxWidth()
            ){
                Text("submit GDPR agreement")
            }
            Spacer(Modifier.height(24.dp))
            Text("Click the button below to revoke GDPR agreement (this action is irreversible). Ensure correct server is entered above. Please wait for confirmation message")

            Button(
                onClick = { showDialog2.value = true },
                modifier = Modifier.padding(16.dp)
                    .fillMaxWidth()
            ) {
                Text("Revoke GDPR Consent")
            }
            /* ----------------------------------------------------------------- */
            /*  Export button – launches the system “Save As” dialog              */
            /* ----------------------------------------------------------------- */
            Spacer(Modifier.height(24.dp))
            Button(
                onClick = { exportLauncher.launch("bonds_export.zip") },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Export bonds & private key")
            }

            /* ----------------------------------------------------------------- */
            /*  Feedback – snackbar and progress overlay                         */
            /* ----------------------------------------------------------------- */
            SnackbarHost(
                hostState = snackbarHostState,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            )
        }
    }

    /* ---------- UI feedback ---------- */
    if (loading) {
        Box(
            Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background.copy(alpha = 0.6f)),
            contentAlignment = Alignment.Center
        ) {
            CircularProgressIndicator()
        }
    }
}

private suspend fun exportAllData(context: Context, destinationUri: Uri, snackbar: SnackbarHostState) {
    withContext(Dispatchers.IO) {
        try {
            // 1️⃣  Create a temporary zip file in memory
            val zipBytes = java.io.ByteArrayOutputStream().use { baos ->
                ZipOutputStream(BufferedOutputStream(baos)).use { zos ->
                    // 1.1  Add all bond files
                    bondsFolder(context).listFiles()?.forEach { file ->
                        if (file.isFile) {
                            ZipEntry(file.name).apply { zos.putNextEntry(this) }
                            BufferedInputStream(FileInputStream(file)).use { bis ->
                                bis.copyTo(zos)
                            }
                            zos.closeEntry()
                        }
                    }

                    // 1.2  Add the private key file (if it exists)
                    val keyFile = File(context.filesDir, "private_key.enc")
                    if (keyFile.exists()) {
                        ZipEntry(keyFile.name).apply { zos.putNextEntry(this) }
                        BufferedInputStream(FileInputStream(keyFile)).use { bis ->
                            bis.copyTo(zos)
                        }
                        zos.closeEntry()
                    }
                }
                baos.toByteArray()
            }

            // 2️⃣  Write the zip bytes to the destination URI
            context.contentResolver.openOutputStream(destinationUri)?.use { out ->
                out.write(zipBytes)
                out.flush()
            }

            withContext(Dispatchers.Main) {
                snackbar.showSnackbar(
                    message = "Export succeeded",
                    actionLabel = "OK",
                    duration = SnackbarDuration.Short
                )
            }
        } catch (e: Exception) {
            Log.e("Export", "Failed to export data", e)
            withContext(Dispatchers.Main) {
                snackbar.showSnackbar(
                    message = "Export failed: ${e.localizedMessage}",
                    actionLabel = "OK",
                    duration = SnackbarDuration.Short
                )
            }
        }
    }
}
@Composable
fun ProfileScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val activity = LocalContext.current as MainActivity

    /* 1️⃣  Observe the stored profile */
    val storedProfile by UserProfileRepository.userProfileFlow(context)
        .collectAsState(initial = UserProfile())

    /* 2️⃣  Local UI state – we initialise it with the stored values. */
    var username by rememberSaveable { mutableStateOf(storedProfile.username) }
    var info by rememberSaveable { mutableStateOf(storedProfile.info) }

    /* 3️⃣  Keep the local state in sync if the stored profile changes
            (e.g. from another screen or a future feature). */
    LaunchedEffect(storedProfile) {
        username = storedProfile.username
        info = storedProfile.info
    }

    val coroutineScope = rememberCoroutineScope()

    val keyboardController = LocalSoftwareKeyboardController.current

    Surface(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Column {
            Text(
                text = "Profile",
                style = MaterialTheme.typography.headlineMedium
            )
            Spacer(Modifier.height(12.dp))

            /* Username field */
            SimpleTextField(
                label = "Username",
                placeholder = "Enter your username",
                text = username,
                onTextChange = { username = it }
            )


            TextField(
                value = info,
                onValueChange = { info = it },
                modifier = Modifier
                    .fillMaxWidth()  // Sets the width of the TextField
                    .heightIn(min = 300.dp)  // Sets a minimum height
                    .padding(16.dp),  // Adds padding
                maxLines = 10,  // Limits the number of lines to 5
                placeholder = { Text("Enter your text here") }
            )

            Spacer(Modifier.height(12.dp))

            /* Save button – writes to DataStore */
            Button(
                onClick = {

                    keyboardController?.hide()
                    coroutineScope.launch {
                        UserProfileRepository.saveProfile(context, username, info)

                        // Update the local HTTP server with the new name/info
                        val nameInfoJson = JSONObject().apply {
                            put("name", username)
                            put("info", info)
                        }
                        //server.updateNameInfo(nameInfoJson.toString())

                        /* ---- Register with the remote server ---- */
                        val regStatus = registerUser(username,info)
                        Log.d("ProfileScreen", "Registration status: $regStatus")
                    }
                },
                modifier = Modifier.align(Alignment.End)
            ) {
                Text("Save")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun UsersScreenPreview() {
    DeCentBondTheme {
        UsersScreen("Android")
    }
}

data class RegistrationRequest(
    val publickey: String,
    val ip: String,
    val nonce: String,
    val signature: String,
    val username: String,
    val info: String
) {
    /** Convert the request to a JSON string – no serialization library needed. */
    fun toJsonString(): String {
        val json = JSONObject()
        json.put("public_key", publickey)
        json.put("ip", ip)
        json.put("nonce", nonce)
        json.put("signature", signature)
        json.put("username", username)
        json.put("info", info)
        return json.toString()
    }
}




/* --------------------------------------------------------------------------- */
/*  Core bond logic – read/write, sign, etc.
   --------------------------------------------------------------------------- */
private val BONDS_DIR = "bonds"

private suspend fun createBond(
    context: Context,
    amount: ULong,
    currency: String,
    receiver: String
): Bond? = withContext(Dispatchers.IO) {

    /* ------------------------------------------------------------------ */
    /*  1️⃣  Grab the key pair that was loaded in the PasswordDialog   */
    /* ------------------------------------------------------------------ */
    val kp = keyPair.value
        ?: run {
            Log.e("Bonds", "Key pair not loaded – cannot sign bond")
            return@withContext null
        }

    /* ------------------------------------------------------------------ */
    /*  2️⃣  Basic fields                                               */
    /* ------------------------------------------------------------------ */
    val sender   = KeyUtils.getPublicKeyPemBase64Url()   // same as kp.public
    val nonce    = generateNonce()                       // 16‑byte hex string
    val now = ZonedDateTime.now(ZoneId.systemDefault())

    /* ------------------------------------------------------------------ */
    /*  3️⃣  Build JSON without the checksum                         */
    /* ------------------------------------------------------------------ */
    val jsonObj = JSONObject().apply {
        put("amount", amount.toLong())
        put("currency", currency)
        put("timedate", now.format(formatter))
        put("sender", sender)
        put("receiver", receiver)
        put("nonce", nonce)
    }

    /* ------------------------------------------------------------------ */
    /*  4️⃣  Sign the JSON payload with the private key                */
    /* ------------------------------------------------------------------ */
    val payloadBytes = jsonObj.toString().toByteArray(Charsets.UTF_8)

    val checksum = try {
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(kp.private)
        signer.update(payloadBytes)
        val sigBytes = signer.sign()

        // Encode raw signature bytes as Base64 (no padding, but you can keep the
        // standard encoder – the server can decode it back).
        Base64.getUrlEncoder().encodeToString(sigBytes)
    } catch (e: Exception) {
        Log.e("Bonds", "Signature error while creating bond", e)
        return@withContext null
    }

    /* ------------------------------------------------------------------ */
    /*  5️⃣  Append checksum and write the bond file                    */
    /* ------------------------------------------------------------------ */
    jsonObj.put("checksum", checksum)

    val file = File(bondsFolder(context), nonce)
    return@withContext try {
        file.writeText(jsonObj.toString())
        Bond(
            amount = amount,
            currency = currency,
            timedate = now.format(formatter),
            sender = sender,
            receiver = receiver,
            nonce = nonce,
            checksum = checksum
        )
    } catch (io: IOException) {
        Log.e("Bonds", "Failed to write bond file", io)
        null
    }
}

private suspend fun writeBond(
    context: Context,
    bond: Bond
) = withContext(Dispatchers.IO) {

    val file = File(bondsFolder(context), bond.nonce)
    return@withContext try {
        file.writeText(bond.toJsonString())
    } catch (io: IOException) {
        Log.e("Bonds", "Failed to write bond file", io)
        null
    }
}

private fun generateNonce(): String {
    val rnd = SecureRandom()
    val bytes = ByteArray(16)
    rnd.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
}

suspend fun syncRemoteBondsToAnalysis(publicKey: String, context: Context) {
    try {
        var analysisBonds = fetchAnalysisBonds(publicKey)

        for(string in analysisBonds)
        {
            val obj = JSONObject(string)
            val nonce = obj.getString("nonce")
            val file = File(analysisFolder(context), nonce)
            file.writeText(string)
        }
        Log.i("BondSync", "Remote bonds copied to analysis folder")
    } catch (e: Exception) {
        Log.e("BondSync", "Failed to sync remote bonds", e)
    }
}