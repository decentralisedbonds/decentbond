package com.example.decentbond

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.material3.AlertDialog

/**
 * Secure password input dialog.
 *
 * - No auto‑complete suggestions.
 * - Clears the internal state immediately after the dialog is dismissed or after a successful
 *   entry – the raw password is never kept in any persistent place.
 * - Hides the keyboard automatically on success or cancel.
 */
@Composable
fun PasswordDialog(
    visible: Boolean,
    title: String,
    onDismiss: () -> Unit,
    onPasswordEntered: (String) -> Unit
) {
    if (!visible) return

    // --- UI state ----------------------------------------------------
    var pwd by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    // --- Focus & IME ------------------------------------------------
    val focusRequester = remember { FocusRequester() }
    val focusManager   = LocalFocusManager.current
    val keyboardCtrl   = LocalSoftwareKeyboardController.current

    // Request focus when the dialog becomes visible
    LaunchedEffect(visible) {
        if (visible) focusRequester.requestFocus()
    }

    // Clean up the password string when the dialog is removed
    DisposableEffect(visible) {
        onDispose { pwd = "" }
    }

    // --- Dialog ------------------------------------------------------
    AlertDialog(
        onDismissRequest = {
            // Clear everything before we actually dismiss
            pwd = ""
            focusManager.clearFocus()
            keyboardCtrl?.hide()
            onDismiss()
        },
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
                        error = ""          // clear previous error on change
                    },
                    label = { Text("Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done,
                        autoCorrect = false
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = {
                            // Re‑use the same submit logic
                            submitPassword(
                                pwd,
                                onSuccess = { enteredPwd ->
                                    // 1️⃣  Clear the UI state
                                    pwd = ""
                                    error = ""
                                    focusManager.clearFocus()
                                    keyboardCtrl?.hide()
                                    // 2️⃣  Call the caller’s callback
                                    onPasswordEntered(enteredPwd)
                                },
                                onError = { msg -> error = msg }
                            )
                        }
                    )
                )
            }
        },

        confirmButton = {
            TextButton(
                onClick = {
                    submitPassword(
                        pwd,
                        onSuccess = { enteredPwd ->
                            pwd = ""              // clear UI state
                            error = ""
                            focusManager.clearFocus()
                            keyboardCtrl?.hide()
                            onPasswordEntered(enteredPwd)
                        },
                        onError = { msg -> error = msg }
                    )
                }
            ) { Text("Unlock") }
        },

        dismissButton = {
            TextButton(
                onClick = {
                    // Same cleanup logic as onDismissRequest
                    pwd = ""
                    focusManager.clearFocus()
                    keyboardCtrl?.hide()
                    onDismiss()
                }
            ) { Text("Reset") }
        }
    )
}

/**
 * Small helper that validates the password and calls the proper callback.
 */
private fun submitPassword(
    pwd: String,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit
) {
    if (pwd.isBlank()) {
        onError("Password cannot be empty")
    } else {
        onSuccess(pwd)
    }
}