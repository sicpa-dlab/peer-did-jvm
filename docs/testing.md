# didcomm-jvm Testing

## Table of Contents

*   [Static Testing](#static-testing)

    *   [Kotlin Linter](#kotlin-linter)

*   [Unit Testing](#unit-testing)

    *   [Local (JVM) Testing](#local-jvm-testing)
    *   [Android Testing](#android-testing)

## Static Testing

### Kotlin Linter

You may run [ktlint](https://github.com/pinterest/ktlint) as follows:

```bash
$ ./gradle ktlintCheck
```

To auto-format:

```bash
$ ./gradlew ktlintFormat
```

## Unit Testing

### Local (JVM) Testing

Local tests can be run as follows:

```bash
$ ./gradlew cleanTest test
```

*   **Notes**:
    *   run from within IDE is an option as well

### Android Testing

The same set of unit tests can be run as [Android instrumented tests](https://developer.android.com/training/testing/unit-testing/instrumented-unit-tests) on emulators or real devices.

Requirements:

*   Java 11 and higher

Preparation steps:

*   enable `android-test` project using Gradle property `androidBuilds=true`
    (e.g. in [gradle.properties](../gradle.properties) or via CLI option `-PandroidBuilds=true`)
*   ensure that either an emulator is [available](https://developer.android.com/studio/run/managing-avds) or real Android device is [attached](https://developer.android.com/studio/run/device)

Run:

*   using Android Studio
*   using gradle

    ```bash
    $ ./gradlew -PandroidBuilds=true :android-test:cleanConnectedAndroidTest :android-test:connectedAndroidTest
    ```
