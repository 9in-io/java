plugins {
    `java-library`
    `maven-publish`
}

// JitPack builds with -Pgroup=com.github.9in-io -Pversion=<tag>; these are the local defaults.
group = "com.github.9in-io"
if (version == Project.DEFAULT_VERSION) version = "0.1.0"
description = "Official Java SDK for 9in: sign-in (OpenID Connect + PKCE), token verification, Management API, adapter and webhooks."

repositories {
    mavenCentral()
}

java {
    withSourcesJar()
    withJavadocJar()
}

// Spring Security 6+ needs Java 17, so the Spring helpers (io.ninein.spring) are compiled for 17
// in their own source set and packed into the same jar. They are only loaded by applications
// that use Spring; everything else is Java 11 bytecode.
val spring: SourceSet = sourceSets.create("spring") {
    compileClasspath += sourceSets.main.get().output
}
val springTest: SourceSet = sourceSets.create("springTest") {
    compileClasspath += sourceSets.main.get().output + spring.output + sourceSets.test.get().output
    runtimeClasspath += sourceSets.main.get().output + spring.output + sourceSets.test.get().output
}

// Signatures of Android API 26 (the minSdk of the Android SDK built on this core), for the
// test that keeps the core Android-safe.
val androidSignature: Configuration = configurations.create("androidSignature") {
    isCanBeConsumed = false
    isTransitive = false
}

dependencies {
    // No runtime dependencies. The framework helpers compile against these and are only
    // loaded when the application has them.
    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")
    "springCompileOnly"("org.springframework.security:spring-security-oauth2-resource-server:6.5.10")
    "springCompileOnly"("org.springframework.security:spring-security-oauth2-jose:6.5.10")

    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("jakarta.servlet:jakarta.servlet-api:6.0.0")
    testImplementation("org.apache.tomcat.embed:tomcat-embed-core:10.1.60")
    testImplementation("org.codehaus.mojo:animal-sniffer:1.24")

    "springTestImplementation"(platform("org.junit:junit-bom:5.14.3"))
    "springTestImplementation"("org.junit.jupiter:junit-jupiter")
    "springTestRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    // Compiled against Spring Security 6.5 (Boot 3.5), tested on 7.0 (Boot 4).
    "springTestImplementation"("org.springframework.security:spring-security-oauth2-resource-server:7.0.9")
    "springTestImplementation"("org.springframework.security:spring-security-oauth2-jose:7.0.9")
    "springTestImplementation"("org.springframework:spring-test:7.0.10")
    "springTestImplementation"("jakarta.servlet:jakarta.servlet-api:6.1.0")

    androidSignature("net.sf.androidscents.signature:android-api-level-26:8.0.0_r2@signature")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-options,-serial,-classfile,-processing", "-parameters"))
}
// String concatenation through StringBuilder instead of invokedynamic: the core runs on Android.
tasks.compileJava { options.compilerArgs.add("-XDstringConcat=inline") }
listOf(spring.compileJavaTaskName, springTest.compileJavaTaskName).forEach { name ->
    tasks.named<JavaCompile>(name) { options.release.set(17) }
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addStringOption("Xdoclint:none", "-quiet")
        links("https://docs.oracle.com/en/java/javase/11/docs/api/")
    }
    exclude("io/ninein/internal/**")
}

tasks.jar {
    from(spring.output)
    manifest {
        attributes(
            "Automatic-Module-Name" to "io.ninein",
            "Implementation-Title" to "9in Java SDK",
            "Implementation-Version" to project.version,
        )
    }
}

tasks.named<Jar>("sourcesJar") {
    from(spring.allSource)
}

val testJavaHome = findProperty("testJavaHome") as String?
val testJavaVersion: Int = testJavaHome?.let { home ->
    val release = file("$home/release")
    val line = if (release.exists()) release.readLines().firstOrNull { it.startsWith("JAVA_VERSION=") } else null
    line?.substringAfter("=")?.trim('"')?.split('.')?.firstOrNull()?.toIntOrNull()
} ?: JavaVersion.current().majorVersion.toInt()

val springTestTask = tasks.register<Test>("springTest") {
    description = "Tests of the Spring Security helpers (Java 17+)."
    group = "verification"
    testClassesDirs = springTest.output.classesDirs
    classpath = springTest.runtimeClasspath
    useJUnitPlatform()
    testJavaHome?.let { executable = "$it/bin/java" }
    onlyIf("Spring Security needs Java 17") { testJavaVersion >= 17 }
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
tasks.check { dependsOn(springTestTask) }

tasks.test {
    useJUnitPlatform {
        // Live end-to-end tests against 9in only run with -Pe2e (or NINE_E2E=1).
        if (!project.hasProperty("e2e") && System.getenv("NINE_E2E") != "1") excludeTags("e2e")
    }
    // Run the tests on another JDK: -PtestJavaHome=/path/to/jdk (CI runs 11, 17, 21 and 25).
    testJavaHome?.let { executable = "$it/bin/java" }
    inputs.files(androidSignature)
    val mainClasses = sourceSets.main.get().output.classesDirs
    doFirst {
        systemProperty("nine.androidSignature", androidSignature.singleFile.absolutePath)
        systemProperty("nine.mainClasses", mainClasses.asPath)
    }
    listOf("NINE_E2E", "NINE_E2E_ENV").forEach { name -> System.getenv(name)?.let { environment(name, it) } }
    if (project.hasProperty("e2e")) environment("NINE_E2E", "1")
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = project.hasProperty("e2e")
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "java"
            from(components["java"])
            pom {
                name.set("9in Java SDK")
                description.set(project.description)
                url.set("https://9in.io/docs/java/")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/license/mit")
                    }
                }
                organization {
                    name.set("Cubelet Ltd")
                    url.set("https://cubelet.co.uk")
                }
                developers {
                    developer {
                        name.set("9in")
                        email.set("support@9in.io")
                        organization.set("Cubelet Ltd")
                    }
                }
                scm {
                    url.set("https://github.com/9in-io/java")
                    connection.set("scm:git:https://github.com/9in-io/java.git")
                }
            }
        }
    }
}
