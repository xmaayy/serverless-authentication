use serde::{Serialize, Deserialize};
use worker::*;

mod utils;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}


#[derive(Serialize, Deserialize)]
pub struct User {
    // We should never be serializing this this though because
    // sending a user password is no bueno
    username: String,
    password: String
}

// First signup request -> no challenge response -> send them a challenge
// that has to be completed and the answer somehow xor'd with their username
// submission
#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);

    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. Alternatively, use `Router::with_data(D)` to
    // provide arbitrary data that will be accessible in each route via the `ctx.data()` method.
    let router = Router::new();
    router
        .get("/", |_, _| Response::ok("The authentication server!"))
        .get_async("/login/:account", |_, ctx| async move {
            // Make sure they're trying to log into an account
            if let Some(id) = ctx.param("account") {
                let accounts = ctx.kv("WEBM_AUTH")?;
                return match accounts.get(id).await? {
                    Some(account) => Response::ok(account.as_string()),
                    None => Response::error("Not found", 404),
                };
            };
            Response::error("Bad Request", 400)
        })
        .get_async("/signup/:account", |_, ctx| async move {
            // Make sure they're trying to log into an account
            if let Some(id) = ctx.param("account") {
                let accounts = ctx.kv("WEBM_AUTH")?;
                return match accounts.put(id, "temppass") {
                    Ok(options) => match options.execute().await {
                        Ok(()) => Response::ok("Added key"),
                        Err(_) => Response::error("Failed to execute", 404),
                    },
                    Err(_) => Response::error("Couldnt Create Options", 404),
                };
            };
            Response::error("Bad Request", 400)
        })
        .post_async("/register", |mut req, ctx| async move {
            let form: User = req.json().await?;
            let username: String = match form.get("username") {
                Some(user) => match user {
                    FormEntry::Field(field) => field,
                    _ => return Response::error("Username was type file", 400),
                },
                None => return Response::error("No username provided", 400),
            };
            let password = match form.get("password") {
                Some(pass) => match pass {
                    FormEntry::Field(field) => field,
                    _ => return Response::error("Username was type file", 400),
                },
                None => return Response::error("No password provided", 400),
            };
            let accounts = ctx.kv("WEBM_AUTH")?;
            return match accounts.put(&username, &password) {
                Ok(options) => match options.execute().await {
                    Ok(()) => Response::ok("Added key"),
                    Err(_) => Response::error("Failed to execute", 404),
                },
                Err(_) => Response::error("Couldnt Create Options", 404),
            };
        })
        .run(req, env)
        .await
}
