Vault Service Broker
====================

[Vault][vault] is a secure credentials storage system from the
fine people over at [Hashicorp][hashicorp].  If you work with
[Cloud Foundry][cf] and [BOSH][bosh], you've probably already
met the [Vault BOSH release][release] over at
[cloudfoundry-community][cfc].

Wouldn't it be awesome if you could use Vault form your Cloud
Foundry applications?

Now you can!

Yes indeed, this here is a _bona fide_ service broker for Vault,
ready to be dropped into your Cloud Foundry and bound to your
applications.


Getting Started
---------------

Before you can do anything, you need a running service broker
somewhere.  The easiest way to do this is to push the broker
itself as a CF application:

```
cf push vault-broker -m 128M -k 256M --no-start
cf set-env vault-broker VAULT_ADDR  "${url}"
cf set-env vault-broker VAULT_TOKEN "${token}"
cf start vault-broker
```

Then, tell Cloud Foundry where the broker is...

```
cf create-service-broker vault ${user} ${pass} ${app_url}
```

(note that `${user}` and `${pass}` will both default to `vault`)

Now, assuming you want to create a service named "secrets", and
attach it to an app named "password-manager":

```
cf create-service vault shared secrets
cf bind-service password-manager secrets
cf restage password-manager
```

All set!


How it Works
------------

Each service provisioned results in a new policy, keyed to the
instance ID.  This policy grants full access to a subset of the
Vault `secret/` backend hierarchy.

When you bind the service to an application, the broker allocates
a new access token for the application to use, and then grants it
access to the services little corner of Vault.  This allows
multiple apps to share a space for secret credentials.

For example, if you create a service named 'secrets', and Cloud
Foundry gives that service the GUID `1234`, the broker will:

1. Create a policy named `1234`, that allows read / write / sudo
   access to the `/secret/1234` path (and everything below).

(that's it)

When that service is bound to an application, Cloud Foundry
assigns it a _binding ID_.  Let's assume that that binding ID is
`ethel`.  The broker will:

1. Create a new access token (assume its "flibbertygibbet")
2. Associate "flibbertygibbet" with the `1234` policy
3. Return the credentials to Cloud Foundry, which consist of:
   - **token** - The access token ("flibbertygibbet")
   - **vault** - The URL to the Vault (see `$VAULT_ADVERTISE_ADDR`,
     in the _Configuration_ section)
   - **root**  - The root path under which to create secrets.  In
     this example, that will be `secret/1234`
4. Record the token in an accounting record, at
   `secret/acct/1234/ethel`.

When a service is unbound, (`cf unbind-service`) the associated
token is revoked, hence the account records!
See?  It's all coming together!

When the service is deprovisioned (`cf delete-service`), the
policy will be removed, and all secrets stored under that services
part of the Vault hierarchy are summarily removed.


Configuration
-------------

The Vault Broker is configured entirely through environment
variables:

  - **$BROKER_GUID** - GUID to use when registering the broker
    with Cloud Foundry.  Defaults to `f89443a4-ae71-49b0-b726-23ee9c98ae6d`
  - **$SERVICE_NAME** - Name of the service, as shown in the
    marketplace.  Defaults to `vault`
  - **$SERVICE_DESC** - A description of the service, also for the
    marketplace.  Defaults to `Vault Secure Storage`
  - **$SERVICE_TAGS** - A set of tags for the service, each
    separated by a comma followed by a space.  By default, no tags
    are configured.
  - **$AUTH_USERNAME** - The username for authenticating
    interaction with Cloud Foundry.  Defaults to `vault`.
  - **$AUTH_PASSWORD** - The password for authenticating
    interaction with Cloud Foundry.  Also defaults to `vault`.
  - **$VAULT_ADDR** - The address to use when accessing the Vault
    to set up new policies and manage provisioned services.  This
    variable is **required**
  - **$VAULT_ADVERTISE_ADDR** - The address to hand out to bound
    applications, along with their credentials.  This defaults to
    `$VAULT_ADDR`, but can be set separately if you need or want
    applications to access the Vault via DNS, or over a load
    balancer.
  - **VAULT_TOKEN** - The token that the service broker will use
    when interacting with the Vault.  This variable is
    **required**, and you probably want to set it to a root token.
  - **VAULT_SKIP_VERIFY** - Instructs the broker to ignore SSL/TLS
    certificate problems (self-signedness, domain mismatch,
    expiration, etc.).  Set this at your own risk.  Note that this
    will not be propagated to bound applications.


[vault]:     https://vaultproject.io
[hashicorp]: https://hashicorp.com
[cf]:        https://cloudfoundry.org
[bosh]:      https://bosh.io
[release]:   https://github.com/cloudfoundry-community/vault-boshrelease
[cfc]:       https://github.com/cloudfoundry-community
