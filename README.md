# entra_saml_logon
Login and intercept one-time-use SAMLResponse before it's sent to the SP.  I use this for APIs that need the SAMLResponse value submitted to a different endpoint than the IdP redirects to.

# SECURITY NOTE:
I wrote the .py files.  You have my word that they don't do anything nefarious.  Even so, I recommend that you perform
your own static analysis and supply chain testing before use.  Many libraries are imported that are not in my own control.

# usage
```
$ python entra_get_saml_response.py
usage: entra_get_saml_response.py [-h] --sp_url SP_URL --username USERNAME --password PASSWORD [--proxies PROXIES]
```

# example
```
$ python entra_get_saml_response.py --sp_url https://MySlackSubDomain.slack.com/sso/saml/start --username MyEntraUsername --password MySecurePassword

```

# NOTE:
For requests-html, the chromium download is hard-coded to a version.  During my testing that revision did not exist.  It can be specified by setting the env var below to a revision that's available and/or otherwise desireable.<br>
`$ export PYPPETEER_CHROMIUM_REVISION=1312423`<br>
`C:\whatever> set PYPPETEER_CHROMIUM_REVISION=1312423`<br>
