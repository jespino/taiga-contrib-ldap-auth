Taiga contrib ldap auth
=======================

The Taiga plugin for ldap authentication.

Installation
------------

### Taiga Back

In your Taiga back python virtualenv install the pip package
`taiga-contrib-ldap-auth` with:

```bash
  pip install taiga-contrib-ldap-auth
```

Modify your settings/local.py and include it on `INSTALLED_APPS` and add your
LDAP configuration:

```python
  INSTALLED_APPS += ["taiga_contrib_ldap_auth"]
  LDAP_SERVER = "ldap://ldap.example.com"
  LDAP_DN_FORMAT = "cn=users,dc=example,dc=com"
  LDAP_UID_FORMAT = "uid"
  LDAP_MAIL_FORMAT = "mail"
  LDAP_FULLNAME_FORMAT = "cn"
  LDAP_BASE_EMAIL = "@example.com"
```

### Taiga Front

Change in your dist/js/conf.json the loginFormType setting to "ldap":

```json
...
    "loginFormType": "ldap",
...
```
