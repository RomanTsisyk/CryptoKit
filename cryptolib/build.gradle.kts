plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.dokka")
    `maven-publish`
    signing
}

android {
    namespace = "io.github.romantsisyk.cryptolib"
    compileSdk = 35

    defaultConfig {
        minSdk = 30
        targetSdk = 35

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

    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all { testTask ->
            testTask.jvmArgs(
                "-XX:+EnableDynamicAgentLoading",
                "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED",
                "--add-opens", "java.base/java.util=ALL-UNNAMED"
            )
        }
    }
}

dependencies {

    implementation ("org.bouncycastle:bcprov-jdk18on:1.78.1")
    testImplementation ("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // ZXing library for QR Code processing
    implementation ("com.google.zxing:core:3.5.3")

    // Android Biometric dependencies
    implementation ("androidx.biometric:biometric:1.1.0")

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
    testImplementation ("io.mockk:mockk-agent-jvm:1.13.12")
    testImplementation ("org.mockito:mockito-core:5.14.2")
    testImplementation ("org.robolectric:robolectric:4.14.1")
    testImplementation ("androidx.test:core:1.6.1")


    // Android instrumentation testing libraries
    androidTestImplementation ("androidx.test.ext:junit:1.2.1")
    androidTestImplementation ("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation ("androidx.work:work-testing:2.10.0")
    androidTestImplementation ("androidx.test:core:1.6.1")

}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml"))
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = findProperty("GROUP").toString()
                artifactId = findProperty("POM_ARTIFACT_ID").toString()
                version = findProperty("VERSION_NAME").toString()

                artifact(sourcesJar)
                artifact(javadocJar)

                pom {
                    name.set(findProperty("POM_NAME").toString())
                    description.set(findProperty("POM_DESCRIPTION").toString())
                    url.set(findProperty("POM_URL").toString())

                    licenses {
                        license {
                            name.set(findProperty("POM_LICENCE_NAME").toString())
                            url.set(findProperty("POM_LICENCE_URL").toString())
                        }
                    }

                    developers {
                        developer {
                            id.set(findProperty("POM_DEVELOPER_ID").toString())
                            name.set(findProperty("POM_DEVELOPER_NAME").toString())
                        }
                    }

                    scm {
                        url.set(findProperty("POM_SCM_URL").toString())
                        connection.set(findProperty("POM_SCM_CONNECTION").toString())
                        developerConnection.set(findProperty("POM_SCM_DEV_CONNECTION").toString())
                    }
                }
            }
        }

        repositories {
            maven {
                name = "sonatype"
                val releasesRepoUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
                val snapshotsRepoUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
                url = if (findProperty("VERSION_NAME").toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl

                credentials {
                    username = findProperty("ossrhUsername") as String?
                        ?: System.getenv("OSSRH_USERNAME")
                    password = findProperty("ossrhPassword") as String?
                        ?: System.getenv("OSSRH_PASSWORD")
                }
            }
        }
    }

    signing {
        val signingKeyId = findProperty("signing.keyId") as String?
            ?: System.getenv("SIGNING_KEY_ID")
        val signingKey = findProperty("signing.key") as String?
            ?: System.getenv("SIGNING_KEY")
        val signingPassword = findProperty("signing.password") as String?
            ?: System.getenv("SIGNING_PASSWORD")

        if (signingKeyId != null && signingKey != null && signingPassword != null) {
            useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
        }

        sign(publishing.publications["release"])
    }
}

