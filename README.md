![](AuthlessBanner.png)
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

## [Demo](https://whoelsebut.me/project/authless)