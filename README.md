# Dead Simple (i.e. last resort) Stateless Authentication
The goal of this repo is to expriment with making a semi-safe, privacy respecting, customizeable user login for 
very basic authentication applications. It's implemented entirely with stateless cloudflare workers, using a
globally available KV store from cloudflare. Useful mostly for small static sites where you dont
want to have to manage any kind of session / state yourself. Because its meant to preserve privacy
(i.e. theres no real validation when someone signs up) you dont know if someones made multiple
accounts, so be wary of cost-overruns from this, though you'll need somewhere in the neighborhood of 
3M accounts in a month to overrun the free tier.

# How It Works
Cloudflare has a lovely *globally available*  key-value store for cloud workers, which just means
we get an infinitely big, free, in memory hashmap to store our users in. Its a key value store, so you
can only technically get one value per user. Fret not! Our 1 'value' can be a nicely serialized JSON
string that we deserialize into a user upon request.

## Problems
### Not all packages support wasm
There was some error `Uncaught Error: LinkError: WebAssembly.Instance(): Import #9 module="env" function="LIMBS_equal" error: function import requires a callable at line 0

### Argon2 Is very slow (intentionally) but we have a 10ms limit
https://security.stackexchange.com/questions/11839/what-is-the-difference-between-a-hash-function-and-a-cryptographic-hash-function
https://github.com/jedisct1/rust-sthash
