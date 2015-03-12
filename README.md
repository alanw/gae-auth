Google AppEngine Auth
=====================

Overview
--------

GAE code that handles account creation and login.

Features
--------

- Create account by supplying email, name and password.
- Verify emails with tokens.
- Login with email and password.
- Logout.
- Password reset with email and token.
- Deactivate account.
- Change name, email and password.

Testing
-------

Install [NoseGAE](https://github.com/Trii/NoseGAE) and run the following:

```sh
nosetests --with-gae test
```
