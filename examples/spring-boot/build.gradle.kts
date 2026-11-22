plugins {
    java
    id("org.springframework.boot") version "4.0.9"
}

repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

dependencies {
    implementation(platform(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("com.github.9in-io:java:v0.1.0")
}
