* feature toggles for admins (LDAP, CAS, EAP-TLS, self managed groups, temp users, user interface parts?, ...)
* internal management over its own IAM roles (should have own namespace or something)?
* self managed groups (maybe with prefix only) with approval processes
* pseudo and second accounts? (managed by a user)
* get rid of XSSes
* implement single logout
* timed and other types of temporary users (qrcode for password)
* user attributes like vlan
* radius mac bypass
* use objectmapper and support at least three db options (in memory, file, socket)
