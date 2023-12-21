# MiniSSO (experimental!)
This is software will maybe one day be a full authentication and authorization solution.
Free of most dependencies like an LDAP backend server.

The idea is to build something for personal home use or small buissnesses (if they want to).

## requirements
```sh
gem install sinatra
gem install sinatra-contrib
gem install webrick
gem install haml
gem install rotp # maybe optional in the future if wanted by some
```

## running
```sh
ruby server.rb
```
You can modify the behavior using the following env vars:
| ENV NAME            | description                                             |
|---------------------|---------------------------------------------------------|
| MINISSO_USERBACKEND | selects a userbackend, can only be one, defaults to ram |
| MINISSO_PROTOCOLS   | selects one or more protocol backends, defaults to all  |

## todo
* ensure security
* finish implementation
	* integrate at least two more backends
	* route logins better internal
	* manage permissions selfhosted
* cleanup webserver integration
	* it was meant to run somewhat secure out of the box... maybe provide a setup script for that usecase instead
* bruteforce protection?
	* multistaged (per user, per IP, ...)
* ???
