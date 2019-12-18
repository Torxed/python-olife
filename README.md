# python-olife
Python bindings for [obtain.life](https://github.com/Torxed/obtain.life).<br>
Used in back-end services to get SSO *(single Sign On)* or to communicate with the obtain.life Identity Management suit *(self-hosted or otherwise)*

Essentiallu a minified version of JWT but a lighter version with Identity Management.

# Features

 * [HS256](https://github.com/Torxed/python-olife/wiki/HS256)
 * <strike>HS384</strike>
 * <strike>HS512</strike>
 * <strike>RS256</strike>
 * <strike>RS384</strike>
 * <strike>RS512</strike>
 * <strike>ES256</strike>
 * <strike>ES384</strike>
 * <strike>ES512</strike>
 * <strike>PS256</strike>
 * <strike>PS384</strike>
 * <strike>PS512</strike>
 * <strike>EdDSA</strike>

# How to use

```python
from olife import obtain_life
life = obtain_life('shared secret if HS256 for instance')
life.subscribe('scientist.cloud', 'shared backend secret, different from shared secret above')

while 1:
	data = life.recv(timeout=0.5)
	life.parse(data)

	# Grab by username defaulting to the domain subscribed above
	print(life.is_logged_in('anton'))
	# Or by username to a custom domain
	print(life.is_logged_in('anton', domain='hvornum.se'))

	# Or check by token-reference, usually submitted by a user
	# upon every request to validate it's authentication state.
	print(life.is_logged_in('A USER SUBMITTED TOKEN'))
```

Note that checking if a user is logged in cross-domain requires a pre-configured shared state between two domains. *(subdomains automatically get a shared state, unless otherwise turned off by the domain owner)*

To register a user, assuming you've set up the domain before hand with the IM. You can use the `register_user` function:

```python
def user_created(data, *args, **kwargs):
	print('User creation response:')
	print(json.dumps(data, indent=4))

life.register_user(user='anton', domain='obtain.life', callback=user_created)
```

To get authentication events pushed from the IM to your back-end service, register a auth hook:

```python
def auth_event(data, *args, **kwargs):
	print('User authentication data:')
	print(json.dumps(data, indent=4))

life.event_hook('auth', auth_event)
```

