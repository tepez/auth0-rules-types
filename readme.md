# auth0-rules-types
> Typescript types for the auth0 rule runtime environment

[![npm version](https://badge.fury.io/js/%40tepez%2Fauth0-rules-types.svg)](https://badge.fury.io/js/%40tepez%2Fauth0-rules-types)

## Install

```
npm install --save @tepez/auth0-rules-types
```

## Usage

The module declares global variables so you should import it, e.g.:

```ts
import '@tepez/auth0-rules-types'
```

It also defines types you can use in the rules:

* `IAuth0RuleUser` - the user object (first argument of the rule function)
* `IAuth0RuleContext` - the context object (second argument of the rule function)
* `IAuth0RuleCallback` - the callback function (third argument of the rule function)
* `IAuthRuleFunction` - the rule function itself

### Add typings for [cache](https://auth0.com/docs/rules/guides/cache-resources)

Add:

```typescript
declare global {
    namespace NodeJS {
        interface Global {
            CACHE_KEY: string
        }
    }
}
```

Now you can access the cache on the global variable, `global.CACHE_KEY`

### Add typings for [rules configuration](https://auth0.com/docs/rules/guides/configuration)

Add:

```typescript
declare global {
    interface IAuth0RuleConfiguration {
        KEY: string
    }
}
```

Now you can access the configuration using `configuration.KEY`
