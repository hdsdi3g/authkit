# REST API
## Summary

 - [ **PUT** /v1/authkit/groups/description](#put-/v1/authkit/groups/description)
 - [ **POST** /v1/authkit/groups/rename](#post-/v1/authkit/groups/rename)
 - [ **DELETE** /v1/authkit/groups/{groupname}/inrole/{rolename}](#delete-/v1/authkit/groups/{groupname}/inrole/{rolename})
 - [ **POST** /v1/authkit/groups/{groupname}/inrole/{rolename}](#post-/v1/authkit/groups/{groupname}/inrole/{rolename})
 - [ **GET** /v1/authkit/groups/{groupname}/roles](#get-/v1/authkit/groups/{groupname}/roles)
 - [ **GET** /v1/authkit/groups/{name}/users](#get-/v1/authkit/groups/{name}/users)
 - [ **DELETE** /v1/authkit/groups/{name}](#delete-/v1/authkit/groups/{name})
 - [ **GET** /v1/authkit/groups](#get-/v1/authkit/groups)
 - [ **POST** /v1/authkit/groups](#post-/v1/authkit/groups)
 - [ **POST** /v1/authkit/me/chpasswd](#post-/v1/authkit/me/chpasswd)
 - [ **GET** /v1/authkit/me/has2auth](#get-/v1/authkit/me/has2auth)
 - [ **GET** /v1/authkit/me/is-external-auth](#get-/v1/authkit/me/is-external-auth)
 - [ **GET** /v1/authkit/me/privacy](#get-/v1/authkit/me/privacy)
 - [ **PUT** /v1/authkit/me/privacy](#put-/v1/authkit/me/privacy)
 - [ **DELETE** /v1/authkit/me/set2auth](#delete-/v1/authkit/me/set2auth)
 - [ **GET** /v1/authkit/me/set2auth](#get-/v1/authkit/me/set2auth)
 - [ **POST** /v1/authkit/me/set2auth](#post-/v1/authkit/me/set2auth)
 - [ **GET** /v1/authkit/rights](#get-/v1/authkit/rights)
 - [ **PUT** /v1/authkit/roles/description](#put-/v1/authkit/roles/description)
 - [ **POST** /v1/authkit/roles/rename](#post-/v1/authkit/roles/rename)
 - [ **GET** /v1/authkit/roles/{name}/groups](#get-/v1/authkit/roles/{name}/groups)
 - [ **DELETE** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context}](#delete-/v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context})
 - [ **POST** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context}](#post-/v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context})
 - [ **GET** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts](#get-/v1/authkit/roles/{rolename}/rights/{rightname}/contexts)
 - [ **DELETE** /v1/authkit/roles/{rolename}/rights/{rightname}](#delete-/v1/authkit/roles/{rolename}/rights/{rightname})
 - [ **POST** /v1/authkit/roles/{rolename}/rights/{rightname}](#post-/v1/authkit/roles/{rolename}/rights/{rightname})
 - [ **GET** /v1/authkit/roles/{rolename}/rights](#get-/v1/authkit/roles/{rolename}/rights)
 - [ **PUT** /v1/authkit/roles/{rolename}/setOnlyForClient](#put-/v1/authkit/roles/{rolename}/setonlyforclient)
 - [ **DELETE** /v1/authkit/roles/{rolename}](#delete-/v1/authkit/roles/{rolename})
 - [ **GET** /v1/authkit/roles](#get-/v1/authkit/roles)
 - [ **POST** /v1/authkit/roles](#post-/v1/authkit/roles)
 - [ **GET** /v1/authkit/users/privacy](#get-/v1/authkit/users/privacy)
 - [ **PUT** /v1/authkit/users/{uuid}/disable](#put-/v1/authkit/users/{uuid}/disable)
 - [ **PUT** /v1/authkit/users/{uuid}/enable](#put-/v1/authkit/users/{uuid}/enable)
 - [ **GET** /v1/authkit/users/{uuid}/groups](#get-/v1/authkit/users/{uuid}/groups)
 - [ **DELETE** /v1/authkit/users/{uuid}/ingroup/{name}](#delete-/v1/authkit/users/{uuid}/ingroup/{name})
 - [ **POST** /v1/authkit/users/{uuid}/ingroup/{name}](#post-/v1/authkit/users/{uuid}/ingroup/{name})
 - [ **GET** /v1/authkit/users/{uuid}/privacy](#get-/v1/authkit/users/{uuid}/privacy)
 - [ **PUT** /v1/authkit/users/{uuid}/privacy](#put-/v1/authkit/users/{uuid}/privacy)
 - [ **PUT** /v1/authkit/users/{uuid}/resetlogontrials](#put-/v1/authkit/users/{uuid}/resetlogontrials)
 - [ **PUT** /v1/authkit/users/{uuid}/switchresetpassword](#put-/v1/authkit/users/{uuid}/switchresetpassword)
 - [ **DELETE** /v1/authkit/users/{uuid}](#delete-/v1/authkit/users/{uuid})
 - [ **GET** /v1/authkit/users/{uuid}](#get-/v1/authkit/users/{uuid})
 - [ **GET** /v1/authkit/users?pos=0&size=0](#get-/v1/authkit/userspos=0&size=0)
 - [ **POST** /v1/authkit/users](#post-/v1/authkit/users)


## **PUT** /v1/authkit/groups/description

setGroupDescription

```javascript
Request body data: {
    description: String,
    name: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: setGroupDescription](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#230)

## **POST** /v1/authkit/groups/rename

renameGroup

```javascript
Request body data: {
    name: String,
    newname: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: renameGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#220)

## **DELETE** /v1/authkit/groups/{groupname}/inrole/{rolename}

removeGroupInRole

Parameters:
 - **groupname** String
 - **rolename** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeGroupInRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#344)

## **POST** /v1/authkit/groups/{groupname}/inrole/{rolename}

addGroupInRole

Parameters:
 - **groupname** String
 - **rolename** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addGroupInRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#333)

## **GET** /v1/authkit/groups/{groupname}/roles

listRolesForGroup

Parameters:
 - **groupname** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        description: String,
        links: [Link, ...],
        name: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listRolesForGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#374)

## **GET** /v1/authkit/groups/{name}/users

listLinkedUsersForGroup

Parameters:
 - **name** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        created: Date,
        enabled: boolean,
        lastlogin: Date,
        ldapDomain: String,
        links: [Link, ...],
        login: String,
        mustChangePassword: boolean,
        realm: String,
        totpEnabled: boolean,
        uuid: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listLinkedUsersForGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#463)

## **DELETE** /v1/authkit/groups/{name}

removeGroup

Parameters:
 - **name** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#262)

## **GET** /v1/authkit/groups

listAllGroups

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        description: String,
        links: [Link, ...],
        name: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listAllGroups](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#272)

## **POST** /v1/authkit/groups

addGroup

```javascript
Request body data: {
    description: String,
    name: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#210)

## **POST** /v1/authkit/me/chpasswd

changeMyPassword

```javascript
Request body data: {
    currentpassword: Password,
    newpassword: Password,
    twoauthcode: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: changeMyPassword](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#99)

## **GET** /v1/authkit/me/has2auth

hasATOTP

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...],
    twoAuthEnabled: boolean
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: hasATOTP](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#175)

## **GET** /v1/authkit/me/is-external-auth

isExternalAuth

```javascript
Response: "application/json;charset=UTF-8" {
    domain: String,
    externalAuthEnabled: boolean,
    links: [Link, ...]
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: isExternalAuth](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#127)

## **GET** /v1/authkit/me/privacy

getPrivacy

```javascript
Response: "application/json;charset=UTF-8" {
    address: String,
    company: String,
    country: String,
    created: Date,
    email: String,
    lang: String,
    links: [Link, ...],
    name: String,
    phone: String,
    postalcode: String,
    userUUID: String
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: getPrivacy](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#204)

## **PUT** /v1/authkit/me/privacy

setPrivacy

```javascript
Request body data: {
    address: String,
    company: String,
    country: String,
    email: String,
    lang: String,
    name: String,
    phone: String,
    postalcode: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: setPrivacy](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#220)

## **DELETE** /v1/authkit/me/set2auth

removeTOTP

```javascript
Request body data: {
    currentpassword: Password,
    twoauthcode: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: removeTOTP](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#186)

## **GET** /v1/authkit/me/set2auth

prepareTOTP

```javascript
Response: "application/json;charset=UTF-8" {
    backupCodes: [String, ...],
    jwtControl: String,
    links: [Link, ...],
    qrcode: String,
    secret: String,
    totpURI: URI
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: prepareTOTP](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#137)

## **POST** /v1/authkit/me/set2auth

confirmTOTP

```javascript
Request body data: {
    controlToken: String,
    currentpassword: Password,
    twoauthcode: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

[Go to the top](#rest-api) &bull; [RestControllerMe :: confirmTOTP](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerMe.java#159)

## **GET** /v1/authkit/rights

getAllRights

```javascript
Response: "application/json;charset=UTF-8" {
    items: [String, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: getAllRights](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#407)

## **PUT** /v1/authkit/roles/description

setRoleDescription

```javascript
Request body data: {
    description: String,
    name: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: setRoleDescription](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#312)

## **POST** /v1/authkit/roles/rename

renameRole

```javascript
Request body data: {
    name: String,
    newname: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: renameRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#302)

## **GET** /v1/authkit/roles/{name}/groups

listLinkedGroupsForRole

Parameters:
 - **name** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        description: String,
        links: [Link, ...],
        name: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listLinkedGroupsForRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#472)

## **DELETE** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context}

removeContextInRight

Parameters:
 - **rolename** String
 - **rightname** String
 - **context** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeContextInRight](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#439)

## **POST** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts/{context}

addContextInRight

Parameters:
 - **rolename** String
 - **rightname** String
 - **context** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addContextInRight](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#427)

## **GET** /v1/authkit/roles/{rolename}/rights/{rightname}/contexts

listContextsForRight

Parameters:
 - **rolename** String
 - **rightname** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [String, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listContextsForRight](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#451)

## **DELETE** /v1/authkit/roles/{rolename}/rights/{rightname}

removeRightInRole

Parameters:
 - **rolename** String
 - **rightname** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeRightInRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#396)

## **POST** /v1/authkit/roles/{rolename}/rights/{rightname}

addRightInRole

Parameters:
 - **rolename** String
 - **rightname** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addRightInRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#385)

## **GET** /v1/authkit/roles/{rolename}/rights

listRightsForRole

Parameters:
 - **rolename** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [String, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listRightsForRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#416)

## **PUT** /v1/authkit/roles/{rolename}/setOnlyForClient

setRoleOnlyForClient

Parameters:
 - **rolename** String

```javascript
Request body data: {
    ip: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: setRoleOnlyForClient](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#322)

## **DELETE** /v1/authkit/roles/{rolename}

removeRole

Parameters:
 - **rolename** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#355)

## **GET** /v1/authkit/roles

listAllRoles

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        description: String,
        links: [Link, ...],
        name: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listAllRoles](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#365)

## **POST** /v1/authkit/roles

addRole

```javascript
Request body data: {
    description: String,
    name: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addRole](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#292)

## **GET** /v1/authkit/users/privacy

getUsersPrivacy

```javascript
Request body data: {
    list: [String, ...]
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        address: String,
        company: String,
        country: String,
        created: Date,
        email: String,
        lang: String,
        links: [Link, ...],
        name: String,
        phone: String,
        postalcode: String,
        userUUID: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: getUsersPrivacy](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#498)

## **PUT** /v1/authkit/users/{uuid}/disable

disableUser

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: disableUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#153)

## **PUT** /v1/authkit/users/{uuid}/enable

enableUser

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: enableUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#164)

## **GET** /v1/authkit/users/{uuid}/groups

listGroupsForUser

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        description: String,
        links: [Link, ...],
        name: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listGroupsForUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#281)

## **DELETE** /v1/authkit/users/{uuid}/ingroup/{name}

removeUserInGroup

Parameters:
 - **uuid** String
 - **name** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeUserInGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#251)

## **POST** /v1/authkit/users/{uuid}/ingroup/{name}

addUserInGroup

Parameters:
 - **uuid** String
 - **name** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addUserInGroup](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#240)

## **GET** /v1/authkit/users/{uuid}/privacy

getUserPrivacy

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    address: String,
    company: String,
    country: String,
    created: Date,
    email: String,
    lang: String,
    links: [Link, ...],
    name: String,
    phone: String,
    postalcode: String,
    userUUID: String
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: getUserPrivacy](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#483)

## **PUT** /v1/authkit/users/{uuid}/privacy

setUserPrivacy

Parameters:
 - **uuid** String

```javascript
Request body data: {
    address: String,
    company: String,
    country: String,
    email: String,
    lang: String,
    name: String,
    phone: String,
    postalcode: String
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: setUserPrivacy](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#508)

## **PUT** /v1/authkit/users/{uuid}/resetlogontrials

resetUserLogonTrials

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: resetUserLogonTrials](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#186)

## **PUT** /v1/authkit/users/{uuid}/switchresetpassword

switchUserMustResetPassword

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: switchUserMustResetPassword](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#175)

## **DELETE** /v1/authkit/users/{uuid}

removeUser

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: removeUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#197)

## **GET** /v1/authkit/users/{uuid}

getUser

Parameters:
 - **uuid** String

```javascript
Response: "application/json;charset=UTF-8" {
    created: Date,
    enabled: boolean,
    lastlogin: Date,
    ldapDomain: String,
    links: [Link, ...],
    login: String,
    mustChangePassword: boolean,
    realm: String,
    totpEnabled: boolean,
    uuid: String
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: getUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#107)

## **GET** /v1/authkit/users?pos=0&size=0

listUsers

```javascript
Response: "application/json;charset=UTF-8" {
    items: [{
        created: Date,
        enabled: boolean,
        lastlogin: Date,
        ldapDomain: String,
        links: [Link, ...],
        login: String,
        mustChangePassword: boolean,
        realm: String,
        totpEnabled: boolean,
        uuid: String
    }, ...],
    links: [Link, ...]
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: listUsers](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#118)

## **POST** /v1/authkit/users

addUser

```javascript
Request body data: {
    userLogin: String,
    userPassword: Password
}
```

```javascript
Response: "application/json;charset=UTF-8" {
    links: [Link, ...],
    realm: String,
    userName: String,
    uuid: String
}
```

_Mandatory rights: SecurityAdmin_

[Go to the top](#rest-api) &bull; [RestControllerUser :: addUser](/blob/master/src/main/java/tv/hd3g/authkit/mod/controller/RestControllerUser.java#96)
