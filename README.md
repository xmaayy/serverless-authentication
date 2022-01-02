# Dead Simple (i.e. last resort) Stateless Authentication
The goal of this repo is to expriment with making a semi-safe, privacy respecting, user login for 
very basic authentication applications. It's implemented entirely with stateless workers, using a
globally available KV store from cloudflare. Useful mostly for small static sites where you dont
want to have to manage any kind of session / state yourself. Because its meant to preserve privacy
(i.e. theres no real validation when someone signs up) you dont know if someones made multiple
accounts, so be wary of cost-overruns from this. 

# How It Works
Cloudflare has a lovely * globally available *  key-value store for cloud workers, which just means
we get an infinitely big, free, in memory hashmap to store our users in. Its a key value store, so you
can only technically get one value per user. Fret not! Our 1 'value' can be a nicely serialized JSON
string that we deserialize into a user upon request.

## Stages
### Signup
1. User fills out the signup form on your page
2. User clicks submit
3. Server responds with a plaintext or captcha challenge to discourage automated account creation
    i. Important to note that the server has not yet stored anything relating to this user, worker invocations are 
    a lot less expensive than extra KV storage invocations ($5/M for KV vs $0.50/M for workers).
4. User solves challenge and resubmits the form with everything included
5. Server creates the user record and responds with the JWT that the user can use 




## Problems
### Not all packages support wasm
There was some error `Uncaught Error: LinkError: WebAssembly.Instance(): Import #9 module="env" function="LIMBS_equal" error: function import requires a callable at line 0

### Argon2 Is very slow (intentionally) but we have a 10ms limit
