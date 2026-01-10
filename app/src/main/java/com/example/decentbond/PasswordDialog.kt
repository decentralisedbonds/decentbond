package com.example.decentbond

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

@Composable
fun PasswordDialog(
    visible: Boolean,
    title: String,
    onDismiss: () -> Unit,          // <-- called when Reset is pressed
    onPasswordEntered: (String) -> Unit
) {
    if (!visible) return

    var pwd by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = { onDismiss() },   // <-- dialog is *not* dismissed automatically
        title = { Text(title) },
        text = {
            Column {
                if (error.isNotEmpty()) {
                    Text(error, color = MaterialTheme.colorScheme.error)
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = pwd,
                    onValueChange = {
                        pwd = it
                        error = ""
                    },
                    label = { Text("Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },

        confirmButton = {
            TextButton(
                onClick = {
                    if (pwd.isBlank()) {
                        error = "Password cannot be empty"
                    } else {
                        onPasswordEntered(pwd)
                    }
                }
            ) {
                Text("Unlock")
            }
        },
        dismissButton = {
            TextButton(
                onClick = { onDismiss() }   // <-- opens the delete‑confirmation dialog
            ) {
                Text("Reset")
            }
        }
    )
}