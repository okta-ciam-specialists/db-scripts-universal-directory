|     | **WARNING**                                                                                                                                                                                                  |
| --: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  ‼️ | _**Everything returned by this script will be set as part of the user profile and will be visible by any of the tenant admins. Avoid adding attributes with values such as passwords, keys, secrets, etc.**_ |
|  ‼️ | _**The `password` parameter of this function is in plain text! Careful what you log.**_                                                                                                                      |

_A list of Node.js modules which can be referenced is available [here](https://tehsis.github.io/webtaskio-canirequire/)_

The following scripts are used to connect CIC to the Okta Universal Directory as a custom database connection.

---

## Authenticating with a JWT

These scripts utilizes Okta's `private_key_jwt` method of authentication rather than the traditional `clientId`/`clientSecret` approach. This method is _slightly_ different for the `login` script versus the others but, in general, the [Build a Self Signed JWT guide](https://developer.okta.com/docs/guides/build-self-signed-jwt/js/main/) provides the applicable details to understand how to authenticate with a JWT.

---

## The Scripts

### Login

This script authenticates a user against Okta's Universal Directory using OAuth2's resource owner grant with PKCE and JWT authentication.

It is executed when a user attempts to log in or immediately after signing up (as a verification that the user was successfully signed up).

_There are three ways this script can finish:_

1. **The user's credentials are valid.**

   See [here](https://auth0.com/docs/users/normalized/auth0/normalized-user-profile-schema) for details on how to format the user profile.

   ```node
   ...
   const profile = {
     user_id: ..., // user_id is mandatory
     email: ...,
     [...]
   };

   return callback(null, profile);
   ```

2. **The user's credentials are invalid.**

```node
return callback(new WrongUsernameOrPasswordError(email, 'my error message'));
```

|     | **Notes**                                                                                                                                                                                                                                                                                                    |
| --: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  👉🏼 | Passing no arguments or a `falsey` first argument to `WrongUsernameOrPasswordError` will result in the error being logged as an `fu` event (invalid username/email) with an empty string for a `user_id`.                                                                                                    |
|  👉🏼 | Providing a truthy first argument will result in the error being logged as an `fp` event (the user exists, but the password is invalid). <br><br>See the [Log Event Type Codes](https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes) documentation for more information about these event types. |

3. **Something went wrong while trying to reach your database.**

```node
return callback(new Error('my error message'));
```

#### Okta Configuration Requirements

1. **Setup a network zone**

   You must add the following IP addresses under SECURITY > NETWORKS > ADD ZONE

   `18.232.225.224, 34.233.19.82, 52.204.128.250, 3.132.201.78, 3.19.44.88, 3.20.244.231`

   ![Image](https://bit.ly/3JTjjq8)

2. **Setup an application for Resource Owner authentication by following [this guide](https://bit.ly/3SQpOy7)**

   - On step #9, rather than selecting 'Client Secret', choose `Public Key / Private Key`.
   - 'Save keys in Okta...'
   - 'Add' a key and follow the prompts. Save your keys offline for use later.

     **Be sure to hit 'Save'!**

     ![Image](https://gist.githubusercontent.com/eatplaysleep/a30e1ffaf71335f559361f145c268c4c/raw/7fc58829d7ebbb35ef0bb83090f481366bdfd5cb/okta_ro_pkce.png)

3. **Enable `id_token` claims**

   By default, the `id_token` contains sparse data. By calling the `/claims` API you can retrieve and subsequently update various system-based `IDENTITY` claims such as: `birthdate`, `family_name`, `given_name`, `picture`, `profile`, `phone_number`, `email_verified`, etc.

   If these claims are not enabled (via API) then the data set in CIC will be limited.

#### Environment Configurations

The following variables must be set and made available via the `configuration` value.

| Key               | Value                                                                         |
| :---------------- | :---------------------------------------------------------------------------- |
| `AUD_LOGIN`       | `https://{your_okta_domain}/oauth2/v1/token`                                  |
| `CLIENT_ID_LOGIN` | _This value should be obtained from the application created in Step 2 above._ |
| `JWK_LOGIN`       | _This value should be obtained from the application created in Step 2 above._ |
| `SCOPES_LOGIN`    | `openid profile email phone address`                                          |

### Create

This script should create a user in Universal Directory. It will be executed when a user attempts to sign up, or when a user is created through the CIC dashboard or API.

When this script has finished executing, the Login script will be executed immediately afterwards, to verify that the user was created successfully.

The user object will always contain the following properties:
| | |
| :--- | --- |
| `email` | the user's email |
| `password` | the password entered by the user, in plain text |
| `tenant` | the name of this Auth0 account |
| `client_id` | the client ID of the application where the user signed up, or API key if created through the API or Auth0 dashboard |
| `connection` | the name of this database connection |

There are three ways this script can finish:

1. A user was successfully created.

```node
return callback(null);
```

2. This user already exists in Universal Directory

```node
return callback(new ValidationError('user_exists', 'my error message'));
```

3. Something went wrong while trying to communicate

```node
return callback(new Error('my error message'));
```

### Get User

This script should retrieve a user profile from Universal Directory without authenticating the user.

It is used to check if a user exists before executing flows that do not require authentication (i.e. signup and password reset).

There are three ways this script can finish:

1. **A user was successfully found.**

The profile should be in a [normalized format](https://auth0.com/docs/users/normalized/auth0/normalized-user-profile-schema).

```node
return callback(null, profile);
```

2. **A user was not found**

   ```node
   return callback(null);
   ```

3. **Something went wrong while trying to reach Universal Directory**

   ```node
   return callback(new Error('my error message'));
   ```

#### Okta Configuration Requirements

1. **Configure OAuth for Okta by following [this guide](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)**

   - When creating a service app, rather than using the default 'Client Secret' option, choose `Public Key / Private Key`.
   - 'Save keys in Okta...'
   - 'Add' a key and follow the prompts. Save the private key for use in configuring the CIC environment.

     **Be sure to hit 'Save'!**

   ![Image](https://gist.githubusercontent.com/eatplaysleep/a30e1ffaf71335f559361f145c268c4c/raw/7fc58829d7ebbb35ef0bb83090f481366bdfd5cb/okta_ro_pkce.png)

2. **Grant Scopes**

   When the guide in step 1 prompts to grant allowed scopes, be sure to grant the following scopes (at a minimum )if you intend on using any user scripts (i.e. `create`, `get`, `changePassword`, etc.):

   `okta.users.manage`
   `okta.users.read`

### Verify Email

This script should mark the current user's email address as verified in Universal Directory.

It is executed whenever a user clicks the verification link sent by email.

These emails can be [customized](https://manage.auth0.com/#/emails).

It is safe to assume that the user's email already exists in Universal Directory, because verification emails, if enabled, are sent immediately after a successful signup.

There are two ways that this script can finish:

1. **The user's email was verified successfully**

   ```node
   return callback(null, true);
   ```

2. **Something went wrong while trying to reach Universal Directory**

   ```node
   callback(new Error('my error message'));
   ```

If an error is returned, it will be passed to the query string of the page where the user is being redirected to after clicking the verification link.

For example, returning `callback(new Error("error"))` and redirecting to `https://example.com` would redirect to the following URL: `https://example.com?email=alice%40example.com&message=error&success=false`.

#### Okta & Environmental Configurations

This script is reliant on the configurations and setup for the `getUser` and `createUser` scripts as outlined above.
