# IMPORTANT NOTE<br/>******************************************************<br/>This repository is always automatically generated from the CAS Initializr. To learn more, please visit the [CAS documentation](https://apereo.github.io/cas).<br/>******************************************************<br/>
Apereo CAS WAR Overlay Template
=====================================

WAR Overlay Type: `cas-overlay`

# Versions
   

- CAS Server `6.5.0-SNAPSHOT`
- JDK `11`
                     
# Build

To build the project, use:

```bash
# Use --refresh-dependencies to force-update SNAPSHOT versions
./gradlew[.bat] clean build
```

To see what commands/tasks are available to the build script, run:

```bash
./gradlew[.bat] tasks
```

If you need to, on Linux/Unix systems, you can delete all the existing artifacts
(artifacts and metadata) Gradle has downloaded using:

```bash
# Only do this when absolutely necessary
rm -rf $HOME/.gradle/caches/
```

Same strategy applies to Windows too, provided you switch `$HOME` to its equivalent in the above command.

# Keystore

For the server to run successfully, you might need to create a keystore file.
This can either be done using the JDK's `keytool` utility or via the following command:

```bash
./gradlew[.bat] createKeystore
```

Use the password `changeit` for both the keystore and the key/certificate entries. 
Ensure the keystore is loaded up with keys and certificates of the server.

## Extension Modules

Extension modules may be specified under the `dependencies` block of the [Gradle build script](build.gradle):

```gradle
dependencies {
    implementation "org.apereo.cas:cas-server-some-module"
    ...
}
```

To collect the list of all project modules and dependencies in the overlay:

```bash
./gradlew[.bat] dependencies
```                                                                       

To see a full list of all project dependencies that are available for configuration and use:

```bash
curl https://localhost:8080/dependencies
```     

Or:

```bash
curl https://localhost:8080/actuator/info
```

# Deployment

On a successful deployment via the following methods, the server will be available at:


* `https://localhost:8443/cas`



  
## Executable WAR

Run the server web application as an executable WAR.

```bash
java -jar build/libs/cas.war
```

Or via:

```bash
./gradlew[.bat] run
```

Debug the CAS web application as an executable WAR:

```bash
./gradlew[.bat] debug
```
       
Or via:

```bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=5000,server=y,suspend=y -jar build/libs/cas.war
```

Run the CAS web application as a *standalone* executable WAR:

```bash
./gradlew[.bat] clean executable
```

## External

Deploy the binary web application file in `build/libs` after a successful build to a servlet container of choice.

# Docker

The following strategies outline how to build and deploy CAS Docker images.

## Jib

The overlay embraces the [Jib Gradle Plugin](https://github.com/GoogleContainerTools/jib) to provide easy-to-use out-of-the-box tooling for
building CAS docker images. Jib is an open-source Java containerizer from Google that lets Java developers build containers using the tools
they know. It is a container image builder that handles all the steps of packaging your application into a container image. It does
not require you to write a Dockerfile or have Docker installed, and it is directly integrated into the overlay.

```bash
./gradlew build jibDockerBuild
```

## Dockerfile

You can also use the native Docker tooling and the provided `Dockerfile` to build and run.

```bash
chmod +x *.sh
./docker-build.sh
./docker-run.sh
```

For convenience, an additional `docker-compose.yml` is also provided to orchestrate the build:

```bash  
docker-compose build
```


# CAS Command-line Shell

To launch into the CAS command-line shell:

```bash
./gradlew[.bat] downloadShell runShell
```

# Retrieve Overlay Resources

To fetch and overlay a CAS resource or view, use:

```bash
./gradlew[.bat] getResource -PresourceName=[resource-name]
```

# Create User Interface Themes Structure

You can use the overlay to construct the correct directory structure for custom user interface themes:

```bash
./gradlew[.bat] createTheme -Ptheme=redbeard
```

The generated directory structure should match the following:

```
├── redbeard.properties
├── static
│ └── themes
│     └── redbeard
│         ├── css
│         │ └── cas.css
│         └── js
│             └── cas.js
└── templates
    └── redbeard
        └── fragments
```

HTML templates and fragments can be moved into the above directory structure, 
and the theme may be assigned to applications for use.

# List Overlay Resources
 
To list all available CAS views and templates:

```bash
./gradlew[.bat] listTemplateViews
```

To unzip and explode the CAS web application file and the internal resources jar:

```bash
./gradlew[.bat] explodeWar
```

# Configuration

- The `etc` directory contains the configuration files and directories that need to be copied to `/etc/cas/config`.

```bash
./gradlew[.bat] copyCasConfiguration
```

- The specifics of the build are controlled using the `gradle.properties` file.

## Configuration Metadata

Configuration metadata allows you to export collection of CAS properties as a report into a file 
that can later be examined. You will find a full list of CAS settings along with notes, types, default and accepted values:

```bash
./gradlew exportConfigMetadata
```                           
