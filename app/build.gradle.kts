import org.gradle.kotlin.dsl.implementation

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    kotlin("plugin.serialization") version "1.8.0"
}

android {
    namespace = "com.example.decentbond"

    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.example.decentbond"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables.useSupportLibrary = true

        ndk {
            //noinspection ChromeOsAbiSupport
            abiFilters += "armeabi-v7a"
            //noinspection ChromeOsAbiSupport
            abiFilters += "arm64-v8a"
            abiFilters += "x86_64"
        }
        // Tell Gradle to invoke CMake for the native code
        externalNativeBuild {
            cmake {
                cppFlags += " -std=c++17 "          // example flag
                // ndkVersion = "23.1.7779620"   // optional: force a specific NDK
            }
        }
    }


    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")   // <‑‑ module‑root
        }
    }



    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
        prefab = true
    }
}

repositories{
//    mavenCentral()
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material3.adaptive.navigation.suite)
    implementation(libs.androidx.room.common.jvm)
    implementation(libs.androidx.room.ktx)
    implementation(libs.firebase.crashlytics.buildtools)
    implementation(libs.play.services.identity.credentials)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.remote.creation.core)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.compose.ui.geometry)
    implementation(libs.androidx.datastore.preferences.core)
    implementation(libs.identity.jvm)
    implementation(libs.androidx.ui)
    implementation(libs.androidx.compiler)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    implementation("com.squareup.okhttp3:okhttp:4.9.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("androidx.compose.ui:ui:1.6.0")
    implementation("androidx.datastore:datastore-preferences:1.2.0")
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("org.jitsi:ice4j:3.2-12-gc2cbf61")
    implementation("androidx.compose.material:material-icons-extended")
    implementation ("com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava")


}
