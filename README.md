# cp-entra-saml

SAML sign-in for the Check Point Identity Awareness Captive Portal (Browser-Based
Authentication) with Microsoft Entra ID, from the command line:

| Command | What it does |
|---|---|
| `setup` | Creates the Entra enterprise application and the Check Point identity provider object, exchanges the values between them, and switches the portal to SAML |
| `status` | Shows what is configured on both sides and whether they agree |
| `teardown` | Puts the portal back and removes what `setup` created |
| `portal` | Opens a live portal as an anonymous browser and reports what it would ask the identity provider for |
| `har` | Reads a browser capture of a failed sign-in and says where it stopped |
| `fingerprint` | Prints a server's certificate fingerprint, to pin the management server |

Python 3.7 or later. No packages to install.

**Status: early.** `har` and `portal` have been run against real captures and a
real portal. `setup`, `status` and `teardown` are covered by unit tests against
fakes and were written from the R82.20 management API reference and the
Microsoft Graph documentation; try them with `--dry-run` and on a test gateway
first.

```
git clone https://github.com/alshawwaf/cp-entra-saml
cd cp-entra-saml
python -m pip install .
cp-entra-saml --help
```

## What you need

**Check Point**

- A management server whose API has the identity-provider commands (present in
  R82.20, API version 2.2). `setup` checks this and stops with a clear message
  if they are missing.
- An administrator with write permission, as an API key or a user name and password.
- Identity Awareness with Browser-Based Authentication already enabled on the gateway.
- The portal published under a path (the default is `https://<gateway>/connect`).
  See [Portal at the root of a host name](#portal-at-the-root-of-a-host-name).

**Microsoft Entra ID**

- An account that can create enterprise applications (Cloud Application
  Administrator or higher).
- Admin consent for the Microsoft Graph permissions the tool asks for:
  `Application.ReadWrite.All`, and with `--assign` also
  `AppRoleAssignment.ReadWrite.All`, `User.ReadBasic.All` and `Group.Read.All`.
  The first two are high-privilege permissions. They are granted to Microsoft's
  own "Microsoft Graph Command Line Tools" application for the signed-in user,
  not to this tool, and nothing is stored after the command ends.

The tool never asks for a Microsoft password. You sign in at Microsoft, either
with a code (`--login device`, the default) or in a browser window
(`--login browser`, for tenants whose Conditional Access blocks the device code
flow). `--use-az-cli` reuses an existing `az login` session instead.

## Credentials for the management server

Kept out of the command line and the shell history. In order of precedence:

1. Environment variables `CP_MGMT_API_KEY`, or `CP_MGMT_USER` and `CP_MGMT_PASSWORD`
2. A file passed with `--credentials`, with the same names as `NAME=value` lines
3. A prompt, when run in a terminal

The management server's certificate is verified. Most management servers use a
certificate your workstation does not trust, so pin it:

```
cp-entra-saml fingerprint 192.0.2.10
# compare the output with the fingerprint shown on the server, then:
cp-entra-saml setup --mgmt 192.0.2.10 --mgmt-fingerprint SHA256:52:58:F4:... ...
```

`--mgmt-ca-file` and `--mgmt-insecure` are the alternatives.

## Set up

See the plan first. Nothing is changed and Entra is not contacted:

```
cp-entra-saml setup --mgmt 192.0.2.10 --mgmt-fingerprint SHA256:... \
    --gateway GW1 --tenant contoso.com --dry-run
```

Then run it:

```
cp-entra-saml setup --mgmt 192.0.2.10 --mgmt-fingerprint SHA256:... \
    --gateway GW1 --tenant contoso.com \
    --assign "Portal Users" --assign alice@contoso.com \
    --install-policy Standard
```

What happens, in this order:

1. Entra: an enterprise application is created from the non-gallery template (or
   an existing one with the same name is reused), switched to SAML, and given a
   signing certificate.
2. Its federation metadata is downloaded, once the new certificate appears in it.
3. Check Point: an identity provider object for the gateway's Identity Awareness
   portal is created from that metadata. The management server answers with the
   gateway's Identifier (Entity ID) and Reply URL.
4. Entra: those two values are written into the application, and the users and
   groups named with `--assign` are allowed to sign in (`--everyone` removes the
   assignment requirement instead).
5. Check Point: the portal's authentication method becomes "identity provider",
   the session is published, and with `--install-policy` the policy is installed.
6. The portal is opened anonymously to confirm that it now redirects to Entra
   with the same Identifier and Reply URL.

If a step fails before the publish, the management session is discarded and
nothing on the gateway changes. The command can be run again at any time: it
finds what already exists and only fills in what is missing.

Useful options:

| Option | Effect |
|---|---|
| `--idp-metadata FILE\|URL` | Any other SAML identity provider (Okta, ADFS, a test IdP). Only the Check Point side is configured; the Identifier and Reply URL are printed for you to enter at the identity provider |
| `--only` | Make this the portal's only identity provider. By default existing ones are kept, and users choose |
| `--idp-name`, `--app-name` | Names of the Check Point object and the Entra application |
| `--domain` | Domain on a Multi-Domain Server |
| `--yes` | No confirmation prompt, for scripts |

### What `setup` does not do

These depend on how you want users and groups to be recognised, so they are
left to you. Check them before the first user signs in.

- **Users the gateway cannot find.** The gateway looks the signed-in name up in
  its user directories. A name it cannot find is accepted only if an External
  User Profile that matches all users (`generic*`) exists.
- **Groups for Access Roles.** Either the identity provider sends them, in a
  claim named `group_attr`, matched to Identity Tags whose external identifier
  is the Entra group's Object ID; or, when the assertion carries no group claim,
  the gateway takes the groups from a directory lookup of the signed-in name.
  Entra sends an e-mail style name, so that lookup has to search by mail rather
  than by account name (the `userLoginAttr` of the gateway's `identity_portal`
  realm). The Identity Awareness Administration Guide, section "SAML Identity
  Provider", describes both.
- **Access to Microsoft before login.** Clients must be able to reach
  `login.microsoftonline.com` while they are still unauthenticated.

## Check

```
cp-entra-saml status --mgmt 192.0.2.10 --mgmt-fingerprint SHA256:... --gateway GW1 --tenant contoso.com
cp-entra-saml portal https://portal.example.com/connect
```

`status` exits with 1 when the two sides disagree. `portal` needs no login and
no management access, so it can be run from a client network: it reports the
login methods the portal offers, each identity provider, and the Entity ID and
Reply URL the gateway sends.

## Read a failed sign-in

Ask the user for a HAR export of the attempt (browser developer tools, Network
tab, "Preserve log" on) and run:

```
cp-entra-saml har signin.har
```

The report says where the flow stopped, compares the gateway's request with the
identity provider's answer (Entity ID, Reply URL, audience, recipient, status,
Entra error codes), and lists the secrets the file contains.

**A HAR export holds the password the user typed.** Browsers strip cookies from
a "sanitized" export but keep form bodies. The report flags this without
printing the value. To pass a capture on:

```
cp-entra-saml har signin.har --sanitize signin-clean.har
```

writes a copy with passwords, cookies, sign-in tokens and identity-provider
page bodies removed. Add `--redact-assertion` to remove the SAML assertion
(names, e-mail address, group memberships) as well. The copy can still be
analysed.

## Portal at the root of a host name

When the Captive Portal's Main URL has no path (`https://portal.example.com/`
instead of `https://portal.example.com/connect`), SAML sign-in has been seen to
fail after the identity provider has accepted the user. The page the gateway
serves to complete the login builds its target as `nacUrl + "/Login"`; at the
root `nacUrl` is `/`, the result is `//Login`, and a browser sends that to a
host named `login`. The user is left on a blank page with no session. Check
Point's documentation shows the portal only under `/connect` and does not
mention this, so treat it as behaviour to test on your version.

`setup` refuses such a portal unless `--allow-root-portal` is given, `status`
and `portal` warn about it, and `har` shows the two lines involved when it finds
them in a capture. The fix is to publish the portal under a path, install
policy, and update the Identifier and Reply URL at the identity provider, since
both contain the path. Run `setup` again to do that update.

## Remove

```
cp-entra-saml teardown --mgmt 192.0.2.10 --mgmt-fingerprint SHA256:... --gateway GW1 \
    --install-policy Standard --tenant contoso.com --delete-entra-app
```

The portal goes back to user name and password (or `--restore-method`), unless
other identity providers remain attached. A deleted Entra application can be
restored from "Deleted applications" for 30 days.

## Limits

- Microsoft's global cloud only. Government and China clouds use other endpoints.
- The management API has no command for the group-claim behaviour or the
  directory lookup attribute; those stay manual, as described above.
- One login attempt by a real user is still the test that counts. `setup` and
  `status` verify configuration, not a user's sign-in.

## Development

```
python -m unittest discover -s tests
```

The tests use synthetic captures and fake servers. Nothing from a real
environment belongs in this repository; `.gitignore` excludes `*.har` and
`*.env`.
