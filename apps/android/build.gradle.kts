plugins {
    id("com.android.application") version "9.4.1"
    id("org.jetbrains.kotlin.android") version "2.3.21"
}

android {
    namespace = "com.example.gotunnels"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.example.gotunnels"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // WireGuard's official tunnel library owns wireguard-go and Android's
    // VpnService integration; this app only supplies validated configuration.
    implementation("com.wireguard.android:tunnel:1.0.20260102")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
}
