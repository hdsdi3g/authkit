# AuthKit documentation technique simplifiée

AuthKit est une application SpringBoot autonome qui expose quelques pages et une API : il n'est donc pas fait pour fonctionner comme cela, mais plutot comme une dépendance Java pour un projet SpringBoot dont il a besoin des services d'AuthKit.

Cette documentation est pour le moment en français (en suivant l'adage, mieux vaut une documentation en français que rien du tout ; les traductions sont les bienvenues).

## Principe de fonctionnement

Quand le package `tv.hd3g.authkit.mod.*` se charge par Spring, la classe `AuthKitSetupWebConfig` charge la classe `ControllerInterceptor` d'intercepter tous les accès clients venant sur la tête HTTP de Spring.

De chaque accès est extrait le controlleur et la méthode appelée. On extrait les annotations `@CheckBefore` de ce controlleur et de cette méthode et on extrait un potentiel `bearer JWT` dans l'entete HTTP `Authorization`.

Le JWT est extrait (vérifié) et l'on compare les droits qu'il liste avec les obligations définies par les `@CheckBefore`. Si cela passe, la requête HTTP s'execute normalement.

En l'absence de JWT pour une methode qui exige des droits particulers, l'utilisateur a sa requête refusée.

## Login

Un controlleur classique (non REST) s'occupe de fournir une page web avec un formulaire d'authentification. L'utilisateur loggé est redirigé vers une page de rebond qui lui donne un JWT pour ses futures requêtes REST.

Certains droits peuvent imposer une adresse IP pour etres acceptés. Le JWT qui est fourni au login contient cette IP. Elle est vérifiée par `ControllerInterceptor` à chaque requete : si cela ne correspond plus (l'utilisateur c'est déplacé d'adresse IP), toutes les requetes seront rejetés.

Il n'y a pas de process de logout coté serveur (pas de session stockés), il faut juste que le client ne se serve plus/détruise son JWT. Il n'y a aucun moyen d'ejecter un utilisateur du serveur, à part changer la clé des JWT de la configuration (tous les utilisateurs auront leurs JWT invalide).

## Audit

Après chaque requête, si il y a la présence d'un `@AuditAfter` dans la methode et/ou le controlleur, une entrée de base de donnée est ajouté avec des informations de trace sur cette action.

## Tests automatiques

Les tests fournis valident toutes les fonctions intégrés, et insistement notament sur ce qui est directement lié à la sécurite, quite a tester plusieurs fois le même bloc de code.

Se sont principalement des tests d'intégrations, des tests de controlleurs, et quelques tests unitaires. Ils se lancent comme n'importe quelques tests automatiques, et nécessitent une configuration cohérente avec une base de donnée dédiée (à configurer en amon).

## Password

La classe `Password` est contraigrante car elle permet :

- un usage unique du mot de passe client : le lire le détruit
- de ne pas stocker un String qui pourait se retrouver stocké dans la JVM en cache (et accessible en cas de memory dump de la JVM)
- de ne pas leaker ce mot de passe dans les logs

## RenforceCheckBefore

L'annotation `@RenforceCheckBefore` oblige `ControllerInterceptor` a tout de même vérifier l'état des droits actuels de l'utilisateur en base avant de valider la requete (potentiellent sensible).

Les groupes LDAP d'un utilisateur qui vient de se connecter (via LDAP donc) sont automatiquement et systématiquement importés en base. On peut bien sur leur donner des Roles comme pour n'importe quel groupe.
