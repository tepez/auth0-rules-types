import { User } from 'auth0'


declare global {
    export interface IAuth0RuleConfiguration {
        /**
         Should be extended by the using module, e.g.:

         declare global {
            interface IAuth0RuleConfiguration {
                DEBUG: string
            }
         }
         */
    }

    const configuration: IAuth0RuleConfiguration;

    class UnauthorizedError extends Error {
        constructor(message: string);
    }


    /*
     It seems the auth0 variable contains a limited instance of an older version of node-auth0
     so we can't use types/auth0 here
     https://auth0.com/docs/rules/current/management-api
    */
    const auth0: {
        /*
         The access_token for the Management API which is available through auth0.accessToken
         is limited to the read:users and update:users scopes
         https://auth0.com/docs/rules/current/management-api
        */
        accessToken: string
        domain: string

        /*
         Found no official documentation for this property, but it appears in many of the sample rules
        */
        baseUrl: string

        users: {
            updateUserMetadata(userId: string, data: any): Promise<any>;
            updateUserMetadata(userId: string, data: any, cb: (err: Error, data: any) => void): void;

            updateAppMetadata(userId: string, data: any): Promise<any>;
            updateAppMetadata(userId: string, data: any, cb: (err: Error, data: any) => void): void;
        }
    }
}


/*
 Source:
 https://auth0.com/docs/user-profile/user-profile-structure
 https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/references/user-object.md
*/
export interface IAuth0RuleUser<AppMetadataType, UserMetadataType> {
    /**
     * @deprecated doesn't appear on the docs
     */
    locale?: string

    /**
     * the `true/false` value indicating if the user has been blocked;
     * @deprecated doesn't appear on the docs
     */
    blocked?: boolean

    /**
     * the IP address associated with the user's last login;
     * @deprecated doesn't appear on the docs
     */
    last_ip: string

    /**
     * the timestamp of when the user last logged in;
     * @deprecated doesn't appear on the docs
     */
    last_login: Date

    /**
     * the number of times the user has logged in;
     * @deprecated doesn't appear on the docs
     */
    logins_count: number

    /*
    the custom fields storing information about a user. These attributes contain information that influences the user's access;
    */
    app_metadata?: AppMetadataType

    /*
    the timestamp of when the user profile was first created
    */
    created_at: Date

    /*
    (unique): the user's email address
    */
    email: string

    /*
    the `true/false` value indicating if the user has verified their email address
    */
    email_verified: boolean

    /*
     the user's last name.
    */
    family_name: string

    /*
    https://auth0.com/docs/user-profile/normalized/auth0
    the user's first name.
    */
    given_name: string

    /*
    the array of objects with information about the user's identities:

    Contains info retrieved from the identity provider with which the user originally authenticates. Users may also link their profile to multiple identity providers; those identities will then also appear in this array. The contents of an individual identity provider object varies by provider, but it will typically include the following:
    In some cases, it will also include an API Access Token to be used with the provider.
    https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_user-prop-identities.md
    */
    identities: {
        /*
         the name of the connection used to authenticate the user;
        */
        connection: string
        /*
         the `true/false` value indicating if the connection is a social one or not;
        */
        isSocial: boolean
        /*
         the entity that is authenticating the user (such as Facebook, Twitter, and so on);
        */
        provider: string

        /*
         the user's unique identifier for this connection/provider.
        */
        user_id: string

        /**
         * User information associated with the connection. When profiles are linked, it is populated with the associated user info for secondary accounts.
         */
        profileData: Record<string, any>
    }[]

    /**
     * Timestamp indicating the last time the user's password was reset/changed. At user creation, this field does not exist. This property is only available for Database connections.
     */
    last_password_reset: Date

    /*
    the list of multifactor providers in which the user is enrolled;
    */
    multifactor: string[]
    /*
    the user's name;
    */
    name: string

    /*
    the user's nickname;
    */
    nickname: string


    /**
     * The permissions assigned to the user's ID token

     */
    permissions: string

    /*
    the user's phone number;
*/
    phone_number: string

    /*
    the `true/false` value indicating whether the user's phone number has been verified (only valid for users with SMS connections);
    */
    phone_verified: boolean

    /*
    the user's profile picture, [click here to learn more about the picture field](/user-profile/user-picture);
*/
    picture: string


    /*
    the timestamp of when the user's profile was last updated/modified;
    */
    updated_at: Date

    /*
(unique): the user's unique identifier;
*/
    user_id: string

    /*
    the custom fields storing information about a user. These attributes should contain information about the user that does not impact what they can or cannot access (such as work and home addresses);
    */
    user_metadata?: UserMetadataType


    /*
    (unique): the user's username.
    */
    username: string
}

export const enum MFAProvider {
    Any = 'any',

    /**
     * @deprecated The guardian and google-authenticator options are legacy settings that are kept for backwards compatibility reasons, and should not be used moving forward. We recommend using any. The 'google-authenticator' option does not let users enroll a recovery code.
     */
    Guardian = 'guardian',

    /**
     * @deprecated The guardian and google-authenticator options are legacy settings that are kept for backwards compatibility reasons, and should not be used moving forward. We recommend using any. The 'google-authenticator' option does not let users enroll a recovery code.
     */
    GoogleAuthenticator = 'google-authenticator',

    Duo = 'duo',
}


/*
 Source:
 https://auth0.com/docs/rules/context-object
 https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/references/context-object.md
*/
export interface IAuth0RuleContext {
    /**
     * A string containing the name of the tenant
     */
    tenant: string

    /*
     the client id of the application the user is logging in to.
    */
    clientID: string

    /*
     the name of the application (as defined on the dashboard).
    */
    clientName: string

    /*
     is an object, whose keys and values are strings, for holding other client properties.
    */
    clientMetadata: Record<string, string>

    /**
     * A string containing the connection's unique identifier
     */
    connectionID: string

    /*
     the name of the connection used to authenticate the user (such as: twitter or some-google-apps-domain)
    */
    connection: string

    /*
     the type of connection. For social connection connectionStrategy === connection. For enterprise connections, the strategy will be waad (Windows Azure AD), ad (Active Directory/LDAP), auth0 (database connections), and so on.
    */
    connectionStrategy: string

    /**
     * An object representing the options defined on the connection.
     */
    connectionOptions: {
        /**
         * a string containing the domain being used for authentication when using an Enterprise connection.
         */
        tenant_domain: string

        /**
         * an array containing the optional domains registered as aliases in addition to the primary domain (specified in the connectionOptions.tenant_domain property).
         */
        domain_aliases: string[]
    }

    /**
     * An object representing metadata defined on the connection. Its keys and values are strings.
     */
    connectionMetadata: Record<string, string>

    /*
    an object that controls the behavior of the SAML and WS-Fed endpoints. Useful for advanced claims mapping and token enrichment (only available for samlp and wsfed protocol).
    */
    samlConfiguration: {}

    /*
     the authentication protocol.
     https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_context-prop-protocol.md
    */
    protocol:
        | 'oidc-basic-profile' /* most used, web based login */
        | 'oidc-implicit-profile' /* used on mobile devices and single page apps */
        | 'oauth2-device-code' /* transaction using the Device Authorization Flow */
        | 'oauth2-resource-owner' /* user/password login typically used on database connections */
        | 'oauth2-resource-owner-jwt-bearer' /* login using a bearer JWT signed with user's private key */
        | 'oauth2-password' /* login using the password exchange */
        | 'oauth2-refresh-token' /* refreshing a token using the Refresh Token exchange */
        | 'samlp' /* SAML protocol used on SaaS apps */
        | 'wsfed' /* WS-Federation used on Microsoft products like Office365 */
        | 'wstrust-usernamemixed' /* WS-trust user/password login used on CRM and Office365 */
        | 'delegation' /* when calling the Delegation endpoint */
        | 'redirect-callback' /* when a redirect rule is resumed */

    /*
     An object containing specific user stats, like stats.loginsCount. Note that any of the counter variables returned as part of the stats object do not increase during silent authentication (as when prompt=none). There are also scenarios where the counter variables might increase yet a rule or set of rules do not execute, as in the case of a successful cross-origin authentication followed by a failed token request.
    */
    stats: {
        loginsCount: number
    } & Record<string, any>

    /*
     this object will contain information about the SSO transaction (if available)
     https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_context-prop-sso.md
    */
    sso: {
        /*
         when a user signs in with SSO to an application where the Use Auth0 instead of the IdP to do Single Sign On setting is enabled.
        */
        with_auth0: boolean

        /*
         an SSO login for a user that logged in through a database connection.
        */
        with_dbconn: boolean

        /*
         client IDs using SSO.
        */
        current_clients: string[]
    }

    /**
     * An object representing the options defined on the Access Token. You can use this object to add custom namespaced claims to the Access Token
     * Custom claims will be included in the Access Token after all rules have run.
     */
    accessToken: {
        /**
         * can be used to change the Access Token's returned scopes
         * When provided, it is an array containing permissions in string format.
         */
        scope: string[]
    } & Record<string, any>

    /*
     An object representing the options defined on the ID Token. Used to add custom namespaced claims to the ID Token. Custom claims will be included in the ID Token after all rules have run.
    */
    idToken: Record<string, any>

    /**
     * After a redirect rule has executed and the authentication transaction is resumed, this property will be populated with the original protocol used to initiate the transaction.
     */
    original_protocol: string

    /**
     * An object representing the multifactor settings used in implementing contextual MFA.
     * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/mfa/guides/customize-mfa-universal-login.md
     */
    multifactor: {
        /**
         * The provider setting is a way to specify whether to force MFA, and which factor to you use. The behavior is different depending if you use the Classic or the New Universal Login experience:
         * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/mfa/guides/customize-mfa-universal-login.md#provider-setting
         */
        provider: MFAProvider

        /**
         * By setting allowRememberBrowser: false, the user will always be prompted for MFA when they login. This prevents the browser cookie from saving the credentials and helps make logins more secure, especially from untrusted machines.
         */
        allowRememberBrowser?: boolean
    },

    /**
     * The object used to implement the redirection of a user from a rule.
     * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/guides/redirect.md
     */
    redirect: {
        url: string
    }

    /*
     An internal identification for the authentication session. Value is kept only if prompt=none is used in the authorization request. Note that the session ID can change after rule execution on other flows, so the value available in context.sessionID might not match the new session ID that the user will receive. This makes this value only meaningful when prompt=none is used.
    */
    sessionID: string

    /**
     * an object containing useful information of the request. It has the following properties:
     * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_context-prop-request.md
     */
    request: {
        /*
         the user-agent of the client that is trying to log in.
        */
        userAgent: string

        /*
         the originating IP address of the user trying to log in.
        */
        ip: string

        /*
         the hostname that is being used for the authentication flow.
        */
        hostname: string

        /*
         an object containing the querystring properties of the login transaction sent by the application.
        */
        query: {
            [key: string]: any
        }

        /*
         the body of the POST request on login transactions used on oauth2-resource-owner, oauth2-resource-owner-jwt-bearer or wstrust-usernamemixed protocols.
        */
        body: any

        /*
         an object containing geographic IP information. It has the following properties:
        */
        geoip: {
            /*
             a two-character code for the country associated with the IP address
            */
            country_code: string

            /*
             a three-character code for the country associated with the IP address
            */
            country_code3: string

            /*
             the country name associated with the IP address
            */
            country_name: string

            /*
             the city or town name associated with the IP address
            */
            city_name: string

            /*
             the latitude associated with the IP address.
            */
            latitude: number

            /*
             the longitude associated with the IP address.
            */
            longitude: number

            /*
             the timezone associated with the IP address.
            */
            time_zone: string

            /*
             a two-character code for the continent associated with the IP address.
            */
            continent_code: string
        }
    }

    /**
     * The unique user id of the primary account for the user. Used to link user accounts from various identity providers.
     */
    primaryUser: string

    /**
     * An object containing information related to the authentication transaction
     * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_context-prop-authentication.md
     */
    authentication: {
        /**
         * n array of objects containing the authentication methods a user has completed during their session
         */
        methods: {
            /**
             * a string representing the name of the authentication method that has been completed. It can be one of the following values (additional values may be supported in the future)
             */
            name:
            /* a social or enterprise connection was used to authenticate the user */
                | 'federated'
                /* a database connection was used to authenticate the user */
                | 'pwd'
                /* a Passwordless SMS connection was used to authenticate the user */
                | 'sms'
                /* a Passwordless Email connection was used to authenticate the user */
                | 'email'
                /* the user completed a multi-factor authentication */
                | 'mfa'

            /**
             * an integer indicating the time in seconds at which the authentication method took place in Unix Epoch time
             */
            timestamp: number
        }[]
    }

    /**
     * An object containing information related to the authorization transaction
     * https://github.com/auth0/docs/blob/6250e6f288e5072f783f4fe646daabeaf7cb67ba/articles/rules/_includes/_context-prop-authorization.md
     */
    authorization: {
        /**
         * an array of strings containing the names of a user's assigned roles
         */
        roles: string[]
    }
}


export interface IAuth0RuleCallback<AppMetadataType, UserMetadataType> {
    (result: Error | string): void

    (result: null,
     user: IAuth0RuleUser<AppMetadataType, UserMetadataType> | User,
     context: IAuth0RuleContext): void
}

export interface IAuthRuleFunction<AppMetadataType, UserMetadataType> {
    (user: IAuth0RuleUser<AppMetadataType, UserMetadataType>,
     context: IAuth0RuleContext,
     callback: IAuth0RuleCallback<AppMetadataType, UserMetadataType>): void
}