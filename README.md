# FROST-Server-OAuth Plugin
This repository contains an OAuth2 / OpenID Connect authentication plugin for [FROST-Server](https://github.com/FraunhoferIOSB/FROST-Server) to be used in combination with the [STAplus](https://github.com/securedimensions/FROST-Server-PLUS) plugin.

This plugin is tested with the Authorization Server [AUTHENIX](https://www.authenix.eu). 

This plugin applies the `sub` value from the OAuth2 TokenInfo response as the `REMOTE_USER`. Technically, the plugin creates a FROST-Server `PrincipalExtended` and adds the entire response from the TokenInfo and UserInfo to the context:

````
PrincipalExtended.name = sub
PrincipalExtended['TokenInfo'] = <response from TokenInfo>
PrincipalExtended['UserInfo'] = <response from UserInfo>
````

The result from the TokenInfo and UserInfo is cached in separate self-expiring ConcurrentHashMap instances. The cache timeout can be configured via `oauth.cacheExpires` with a default of 60 seconds.

## Deployment
The deployment of the STAplus plugin requires a working deployment of the FROST-Server and the STAplus plugin.

### Build the OAuth2 plugin
This repository builds with the FROST-Server 2.2.0 SNAPSHOT.

The command `mvn install` produces the JAR file `FROST-Server.Auth.OAuth2-2.2.0-SNAPSHOT.jar`. Make sure you copy the JAR-file to the appropriate FROST-Server directory.

## Settings
You can enable this plugin in FROST-Server and configure the behavior by modifying the FROST-Server `context.xml` file.

### Activate the plugin
The plugin is activated by adding the `auth.provider` parameter to the file `context.xml`:

```xml
<Parameter override="false" name="auth.provider" value="de.securedimensions.frostserver.auth.oauth2.OAuth2AuthProvider" description="The java class used to configure authentication/authorisation."/>
```

The realm for the Authentication challenge can be configured via 
```xml
<Parameter override="false" name="auth.realmName" value="FROST-Server-STAplus" />
```

### Authorization Behavior
This plugin can be configured to make authentication optional for HTTP GET which enables anonymous read. To activate anonymous read, please add the following parameter to `context.xml`:

```xml
<Parameter override="false" name="auth.allowAnonymousRead" value="true" />
```

The plugin can also be configured to undertake authentication only (so no authorization on roles is enforced) by adding the following parameter to `context.xml`:

```xml
<Parameter override="false" name="auth.authenticateOnly" value="true" />
```

To enforce simple role based authorization, it is possible to provide the role required for read, create, update and delete. Also, the admin role can configured this way:

```xml
<Parameter override="false" name="auth.role.read" value="..." />
<Parameter override="false" name="auth.role.create" value="..." />
<Parameter override="false" name="auth.role.update" value="..." />
<Parameter override="false" name="auth.role.delete" value="..." />
<Parameter override="false" name="auth.role.admin" value="..." />
```

### Configure the user identifier that gets admin role
Please add the `auth.adminUid` to the configuration. If using AUTHENIX for authentication, the REMOTE_USER is identified by a UUIDv3.

```xml
<Parameter override="false" name="auth.adminUid" value="<user identifier>" />
```

### Configure the Authorization Server
The following configuration reflects the use of AUTHENIX.  

```xml
    <Parameter override="false" name="auth.oauth.introspectionUrl" value="https://www.authenix.eu/oauth/tokeninfo" />
    <Parameter override="false" name="auth.oauth.userinfoUrl" value="https://www.authenix.eu/openid/userinfo" />
    <Parameter override="false" name="auth.oauth.scope" value="openid" />
    <Parameter override="false" name="auth.oauth.clientId" value="<client_id>" />
    <Parameter override="false" name="auth.oauth.clientSecret" value="<client_secret>" />
```
The `client_id` and `client_secret` can be obtained from registering the plugin as a `Service` with [AUTHENIX register app](https://www.authenix.eu/users/registerapp).

The `auth.oauth.cacheExpires` parameter allows to configure the timeout for the token and user info cache:

```xml
<Parameter override="false" name="auth.oauth.cacheExpires" value="60" />
```

