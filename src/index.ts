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

    // It seems the auth0 variable contains a limited instance of an older version of node-auth0
    // so we can't use types/auth0 here
    // https://auth0.com/docs/rules/current/management-api

    const auth0: {
        // The access_token for the Management API which is available through auth0.accessToken
        // is limited to the read:users and update:users scopes
        // https://auth0.com/docs/rules/current/management-api
        accessToken: string
        domain: string

        // Found no official documentation for this property, but it appears in many of the sample rules
        baseUrl: string

        users: {
            updateUserMetadata(userId: string, data: any): Promise<any>;
            updateUserMetadata(userId: string, data: any, cb: (err: Error, data: any) => void): void;

            updateAppMetadata(userId: string, data: any): Promise<any>;
            updateAppMetadata(userId: string, data: any, cb: (err: Error, data: any) => void): void;
        }
    }
}

export interface IAuth0RuleUser<AppMetadataType, UserMetadataType> {
    // This does not appear on the https://auth0.com/docs/user-profile/user-profile-structure page
    locale?: string

    // Source:
    // https://auth0.com/docs/user-profile/user-profile-structure
    // https://github.com/auth0/docs/blob/a5c07513dc15818e3162098a5d87b25c795f11e3/articles/user-profile/user-profile-structure.md

    // the custom fields storing information about a user. These attributes contain information that influences the user's access;
    app_metadata?: AppMetadataType

    //the `true/false` value indicating if the user has been blocked;
    blocked?: boolean

    //the timestamp of when the user profile was first created
    created_at: Date

    //(unique): the user's email address
    email: string

    //the `true/false` value indicating if the user has verified their email address
    email_verified: boolean

    //the array of objects with information about the user's identities:
    identities: {
        // the name of the connection used to authenticate the user;
        connection: string
        // the `true/false` value indicating if the connection is a social one or not;
        isSocial: boolean
        // the entity that is authenticating the user (such as Facebook, Twitter, and so on);
        provider: string

        // the user's unique identifier for this connection/provider.
        user_id: string
    }[]

    //the list of multifactor providers in which the user is enrolled;
    multifactor: string[]

    //the IP address associated with the user's last login;
    last_ip: string

    //the timestamp of when the user last logged in;
    last_login: Date

    // the number of times the user has logged in;
    logins_count: number

    //the user's name;
    name: string

    //the user's nickname;
    nickname: string

    //the user's phone number;
    phone_number: string

    //the `true/false` value indicating whether the user's phone number has been verified (only valid for users with SMS connections);
    phone_verified: boolean

    //the user's profile picture, [click here to learn more about the picture field](/user-profile/user-picture);
    picture: string

    //the timestamp of when the user's profile was last updated/modified;
    updated_at: Date

    //(unique): the user's unique identifier;
    user_id: string

    //the custom fields storing information about a user. These attributes should contain information about the user that does not impact what they can or cannot access (such as work and home addresses);
    user_metadata?: UserMetadataType

    //(unique): the user's username.
    username: string

    // https://auth0.com/docs/user-profile/normalized/auth0
    // the user's first name.
    given_name: string

    // the user's last name.
    family_name: string
}

export interface IAuth0RuleContext {
    // https://auth0.com/docs/link-accounts#automatic-account-linking
    primaryUser: string

    // Source:
    // https://auth0.com/docs/rules/current/context
    // https://github.com/auth0/docs/blob/a2b5ed6f159dcdc54804e587edf6ffca66206502/articles/rules/current/context.md

    // the client id of the application the user is logging in to.
    clientID: string

    // the name of the application (as defined on the dashboard).
    clientName: string

    // is an object, whose keys and values are strings, for holding other client properties.
    clientMetadata: {
        [key: string]: string
    }

    // the name of the connection used to authenticate the user (such as: twitter or some-google-apps-domain)
    connection: string

    // the type of connection. For social connection connectionStrategy === connection. For enterprise connections, the strategy will be waad (Windows Azure AD), ad (Active Directory/LDAP), auth0 (database connections), and so on.
    connectionStrategy: string

    // an object that controls the behavior of the SAML and WS-Fed endpoints. Useful for advanced claims mapping and token enrichment (only available for samlp and wsfed protocol).
    samlConfiguration: {
        // the authentication protocol.
        protocol: 'oidc-basic-profile' // most used, web based login
            | 'oidc-implicit-profile' // used on mobile devices and single page apps
            | 'oauth2-resource-owner' // user/password login typically used on database connections
            | 'oauth2-resource-owner-jwt-bearer' // login using a bearer JWT signed with user's private key
            | 'oauth2-password' // login using the password exchange
            | 'oauth2-refresh-token' // refreshing a token using the Refresh Token exchange
            | 'samlp' // SAML protocol used on SaaS apps
            | 'wsfed' // WS-Federation used on Microsoft products like Office365
            | 'wstrust-usernamemixed' // WS-trust user/password login used on CRM and Office365
            | 'delegation' // when calling the Delegation endpoint
            | 'redirect-callback' // when a redirect rule is resumed
    }

    // an object containing specific user stats, like stats.loginsCount.
    stats: any

    // this object will contain information about the SSO transaction (if available)
    sso: {
        // when a user signs in with SSO to an application where the Use Auth0 instead of the IdP to do Single Sign On setting is enabled.
        with_auth0: boolean

        // an SSO login for a user that logged in through a database connection.
        with_dbconn: boolean

        // client IDs using SSO.
        current_clients: string[]
    }

    // used to add custom namespaced claims to the access_token.
    accessToken: any

    // used to add custom namespaced claims to the id_token.
    idToken: any

    // unique id for the authentication session.
    sessionID: any

    // an object containing useful information of the request. It has the following properties:
    request: {
        // the user-agent of the client that is trying to log in.
        userAgent: string

        // the originating IP address of the user trying to log in.
        ip: string

        // the hostname that is being used for the authentication flow.
        hostname: string

        // an object containing the querystring properties of the login transaction sent by the application.
        query: {
            [key: string]: any
        }

        // the body of the POST request on login transactions used on oauth2-resource-owner, oauth2-resource-owner-jwt-bearer or wstrust-usernamemixed protocols.
        body: any

        // an object containing geographic IP information. It has the following properties:
        geoip: {
            // a two-character code for the country associated with the IP address
            country_code: string

            // a three-character code for the country associated with the IP address
            country_code3: string

            // the country name associated with the IP address
            country_name: string

            // the city or town name associated with the IP address
            city_name: string

            // the latitude associated with the IP address.
            latitude: number

            // the longitude associated with the IP address.
            longitude: number

            // the timezone associated with the IP address.
            time_zone: string

            // a two-character code for the continent associated with the IP address.
            continent_code: string
        }
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