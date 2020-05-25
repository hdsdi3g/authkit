# AuthKit Contributing

Respect classic Java code formating. Please read and understood USAGE.md and SECURITY.md documentations.

## Code organisation
 - In root package `tv.hd3g.authkit`, put only code for let App in standalone mode to run.
 - In sub package `tv.hd3g.authkit.mod.*` put all "real" fonctionnal code: this way let embedding Autkit as Spring Module for other projects.

New configuration entries must to be declared in `src/main/java/META-INF/additional-spring-configuration-metadata.json`. Eclipse with SpringBoot plugins can help you.

Before send a PR for code evolution, or adding a new function, please check if:
 - INSTALL.md still ok, or else update it in PR.
 - Idem for README.md
 - This file should never change during code/function changes. Idem for LICENCE
 - Prepare an explicit but not too technical resume for the changes an put in the top of CHANGELOG.md, _without add version_.

## Commits rules
 - Don't forget to add git hooks before commit.
 - Rebase commits on last the MASTER git commit before pull-request.
 - New commit names _must_ reference a GitHub issue id and name.
 - You should not mix multiple issues in one commit
 - You can mix issues in multiple commits in one pull-request (but only one subject by pull-request).

## Automatic tests checks
 - All automatic test must always pass. If some tests needs a specific setup, like an LDAP Server by example, they have to adapt with the presence or absence of configuration keys.
 - A new function, new controller must be tested at the least one time on a new integration test.
 - A new service must be fully tested with new integrations test.
 - A DTO or a simple object must be tested with a full unit test.
 - If existing functions have their internal behavior changed, or with new options, existing integration tests should be updated to check the new behavior jointly with the actual.

## Database
UTF-8, GMT only. No Procedures, no Views, no Triggers.

All databases and schema changes must to be done via Liquibase, in `src/main/resources/db/database-changelog.xml` and in sub dir XML files. And always set the `<rollback>` zone.

Never forget to update `scripts/drop-db.sh` if you create new tables.

You must cypher all personnal informations before add-it in database.

## Exceptions
Throws AuthKitException only in code called by REST Controllers, especially by services.

Never forget:
 - RuntimeException like AuthKitException will cancel operations in transations
 - Classic Exceptions, and specific Exceptions can cancel, or not transations

Classic exceptions should be logged, rare exceptions must be logged. Important/security concern exceptions must be logged and added to Audit.

Never, never display in logs or Audit user privacies founded in table Userprivacy.

## New release process

- Mergue all validated (and master rebased) pull requests
- Do a last full automatic tests checks
- Change the maven version (remove the "-SNAPSHOT"), add it in CHANGELOG.md and commit the both files
- `git tag` the new version
- Change the maven version N = Z+1 as X.Y.N-SNAPSHOT and commit it. If the future release need another version increment (like a major increment), create a new commit for it _before_ mergue new pull requests.
 - update if needed the API.md (run `export-rest-doc-api` Spring command line)

## Dependencies

Add new Maven dependencies in `pom.xml` file. Please choose the more time stable and the more serious-security stable technologies. And only free/OSI softwares.

Update dependencies can be a needs or security mandatory. Please ensure the automatic tests still ok after upgrades.

Never push a pull-request with only a pom.xml dependencies update, **except** where is a security breach in dependencies, and after do a full automatic tests pass.

## Code owner

Propose code only with a free/OSI compatible licence. LGPL v3 is encouraged.

Respect original source owner an licence even from StackOverflow if you're not the original author.

Code modification must keep the original file licence. Free feel to add your references on the licence block.
