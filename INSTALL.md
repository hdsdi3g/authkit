# AuthKit Installation

Installation can be doing in the main project who needs AuthKit, or as stand-alone for testing/debug/developpement needs.

## Requirement

A correctly setup of **OpenJDK 11.x**. AdoptOpenJDK distributions will be fine. No matter for Windows, macOS or Linux.

Main project needs to work with **Spring Boot v2.1.7.RELEASE**. It's not tested with others versions.

Database technology is validated on **MySQL 8.x, community server GPL**. It can run on any Hibernate compatible databases (in this case, you must adapt manually all the Liquibase declarations).

**Apache Maven 3.6.x** for building, **git** for retrive code (some setup tools needs git) and some **bash** for simple shortcut scripts.

## Full setup

`git clone` sources from GitHub.

### For use AuthKit in a maven project

And add dependency to your new project pom.xml:

```xml
<dependency>
  <groupId>tv.hd3g</groupId>
  <artifactId>authkit</artifactId>
  <version>VERSION</version>
</dependency>
```

Replace VERSION by the last published version.

### AuthKit developpement

Please setup an `application.yml` and `log4j2.xml` in `/config`. You can use samples in `src/test/resources`, or just ignore `/config` and keep the ones in `resources` (`/config` is outside git control).

After, run:

```shell
mvn setupdb:deploy
```

for deploy the database configuration, and use:

```shell
mvn setupdb:dropall
```

for a full reverse setup. More information on setupdb in [setupdb's README](https://github.com/hdsdi3g/setupdb-maven-plugin/blob/master/README.md).

_For maven calls, you can stop internal tests and gpg jar sign with:_

```shell
mvn <verbs> -DskipTests=true -Dgpg.skip=true
```

For update API.md, use:

```shell
scripts/make-rest-doc.sh
```

### AuthKit as library or in production

If you wan't use Liquibase outside maven, please generate a `/target/database-full-archive-changelog.xml` with:

```shell
mvn setupdb:archive
```

And you will be able to use, with a valid setup, **Liquibase v3.x** with the MySQL JDBC connector **mysql-connector-java-8.x.jar** putted in the liquibase setup **lib** directory.

More information on [Liquibase doc site](https://docs.liquibase.com/).

### AuthKit configuration

Create/edit _log4j2.xml_ in classpath. Nothing special, just don't forget it. An example is provided in `scripts/log4j2-tests.xml` (good for automated tests) and in `src/test/resources`.

Create/edit _application.properties_ or _application.yml_. And YAML file for example and test purpose is provided also in `src/test/resources`. You should take care of:

- `spring.datasource.url`, `username` **and** `password`
- `spring.datasource.driver-class-name` _or_ `spring.jpa.properties.hibernate.dialect`
- `server.port`
- `authkit.realm`, used for specific Authkit needs. You **MUST** set `jwt_secret` and `cipher_secret` with _secret-generator_ the sames for all shared database access and websites backends instance.

### AuthKit secret-generator

Just starts `java scripts/secret-generator.java` and get new secrets in `secret-application.yml`. After get entries, you can delete `secret-application.yml` file.

### Build Spring Boot App

You can build App:

- just AuthKit for standalone operations
- your app with AuthKit in dependencies

Add the spring-boot-maven-plugin in `pom.xml` (it's already done for authkit pom file):

```xml
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <executions>
        <execution>
            <goals>
                <goal>repackage</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

And starts `mvn package -DskipTests=true -Dgpg.skip=true`

### Create security admin

After build, prepare a config directory containing an `application.yml` or `application.properties`, and run:

```bash
scripts/create-security-admin.sh
```

Or, manually:

```bash
export AUTHKIT_NEWADMIN=<security admin login name>
export AUTHKIT_PASSWORD=<security admin password>
java -jar myspringapp.jar create-security-admin
```

The newer created security admin will have all code declared rights. Repeat operation for another admin, for overwrite actual admin password, during troubleshooting, or if you needs too add all newer rights in one shot.

## Upgrade

Prepare a database upgrade environment based on setup (Liquibase and `database-full-archive-changelog.xml` file).

Upgrading AuthKit may require:

- to update database before upgrade
- to update database after upgrade
- to add or change configuration entries

So, please read CHANGELOG.md, and do database and configuration adaptations.

For all cases, database updating will be managed by Liquibase, and _should be_ reversible.
