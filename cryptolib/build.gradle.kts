plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.dokka")
}

android {
    namespace = "io.github.romantsisyk.cryptolib"
    compileSdk = 35

    defaultConfig {
        minSdk = 30

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {

    implementation ("org.bouncycastle:bcprov-jdk15on:1.70")

    // ZXing library for QR Code processing
    implementation ("com.google.zxing:core:3.5.3")

    // Android Biometric dependencies
    implementation ("androidx.biometric:biometric:1.4.0-alpha02")

    // Security and cryptographic libraries
    implementation ("androidx.security:security-crypto:1.1.0-alpha06")

    // AndroidX Core libraries
    implementation ("androidx.core:core-ktx:1.15.0")
    implementation ("androidx.appcompat:appcompat:1.7.0")

    // Material Design components
    implementation ("com.google.android.material:material:1.12.0")

    // WorkManager for background tasks
    implementation ("androidx.work:work-runtime-ktx:2.10.0")

    // Unit testing libraries
    testImplementation ("junit:junit:4.13.2")
    testImplementation ("io.mockk:mockk:1.13.12") // Or
    testImplementation ("org.mockito:mockito-core:5.14.2")
    testImplementation ("org.robolectric:robolectric:4.14.1")


    // Android instrumentation testing libraries
    androidTestImplementation ("androidx.test.ext:junit:1.2.1")
    androidTestImplementation ("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation ("androidx.work:work-testing:2.10.0")
    androidTestImplementation ("androidx.test:core:1.6.1")

}

