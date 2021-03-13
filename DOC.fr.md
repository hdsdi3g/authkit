# AuthKit documentation technique simplifiée

AuthKit est une application SpringBoot autonome qui expose quelques pages et une API : il n'est donc pas fait pour fonctionner comme cela, mais plutôt comme une dépendance Java pour un projet SpringBoot dont il a besoin des services d'AuthKit.

Cette documentation est pour le moment en français (les traductions sont les bienvenues).

## Principe de fonctionnement

Quand le package `tv.hd3g.authkit.mod.*` est chargé par Spring, la classe `AuthKitSetupWebConfig` charge la classe `ControllerInterceptor` d'intercepter tous les accès clients venant sur la tête HTTP de Spring.

De chaque demande d'accès est extrait le contrôleur et la méthode appelée. On extrait les annotations `@CheckBefore` de ce contrôleur et de cette méthode et on extrait un potentiel `bearer JWT` dans l'entête HTTP `Authorization`, et/ou un cookie (le cookie et le bearer ont des JWT produits par la même source, et sont interchangeables).

Le JWT est extrait (vérifié) et l'on compare les droits qu'il liste avec les obligations définies par les `@CheckBefore`. Si cela passe, la requête HTTP s'execute normalement.

Si le contrôleur est REST, alors seul le Bearer peut l'authentifier. Si le contrôleur n'est pas REST (`@Controller`) le Cookie ou le Bearer peuvent l'authentifier, seulement pour les requêtes GET ou POST.

En l'absence de JWT pour une méthode qui exige des droits particuliers, l'utilisateur a sa requête refusée.

## Login

Un contrôleur classique (non REST) s'occupe de fournir une page web avec un formulaire d'authentification. L'utilisateur logué est redirigé vers une page de rebond qui lui donne un JWT pour ses futures requêtes REST (via Bearer) ou non-REST (Cookie).

Certains droits peuvent imposer une adresse IP pour êtres acceptés. Le JWT qui est fourni au login contient cette IP. Elle est vérifiée par `ControllerInterceptor` à chaque requête : si cela ne correspond plus (l'utilisateur c'est déplacé d'adresse IP), toutes les requêtes seront rejetés.

Il n'y a pas de process de logout coté serveur (pas de session stockés) pour les contrôleurs REST, il faut juste que le client ne se serve plus/détruise son JWT. Il n'y a aucun moyen d'éjecter un utilisateur du serveur, à part changer la clé des JWT de la configuration et de le relancer (tous les utilisateurs auront leurs JWT invalide). C'est le coté stateless des JWT qui est utilisé.

En non-REST, une simple suppression du cookie d'authentification suffit à la déconnexion.

Si un utilisateur tente d'accéder à une ressource pour laquelle il doit être connecté, il lui sera demandé de se connecter avant. Le chemin de cette ressource [sera stocké dans un cookie](https://github.com/hdsdi3g/authkit/issues/29), et après avoir validé le login, la page redirigée ne sera pas celle qui est prévue, mais celle indiquée par le cookie qu’il fournira.

## Audit

Après chaque requête, si il y a la présence d'un `@AuditAfter` dans la méthode et/ou le contrôleur, une entrée de base de donnée est ajouté avec des informations de trace sur cette action.

## Tests automatiques

Les tests fournis valident toutes les fonctions intégrés, et insistent notamment sur ce qui est directement lié à la sécurité, quitte à tester plusieurs fois le même bloc de code.

Se sont principalement des tests d'intégrations, des tests de contrôleurs, et quelques tests unitaires. Ils se lancent comme n'importe quelques tests automatiques, et nécessitent une configuration en particulier (H2 en mémoire sera utilisé).

## Password

La classe `Password` est contraignante car elle permet :

- un usage unique du mot de passe client : le lire le détruit
- de ne pas stocker un String qui pourrait se retrouver stocké dans la JVM en cache (et accessible en cas de memory dump de la JVM)
- de ne pas leaker ce mot de passe dans les logs

## RenforceCheckBefore

L'annotation `@RenforceCheckBefore` oblige `ControllerInterceptor` a tout de même vérifier l'état des droits actuels de l'utilisateur en base avant de valider la requête (potentiellement sensible).

Les groupes LDAP d'un utilisateur qui vient de se connecter (via LDAP donc) sont automatiquement et systématiquement importés en base. On peut bien sur leur donner des Roles comme pour n'importe quel groupe.
