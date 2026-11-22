plugins {
    application
}

repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.9in-io:java:v0.1.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
}

application {
    mainClass.set("example.WebApp")
}
