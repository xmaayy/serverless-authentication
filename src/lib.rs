use serde::{Deserialize, Serialize};
use worker::*;

mod user;
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

#[derive(Deserialize)]
pub struct User {
    // We should never be serializing this this though because
    // sending a user password is no bueno
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserResponse {
    // We should never be serializing this this though because
    // sending a user password is no bueno
    username: String,
    token: String,
}

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
        .post_async("/validate", |mut req, _| async move {
            let json_user: UserResponse = req.json().await?;
            match user::validate_jwt(json_user.token) {
                Ok(_) => Response::ok("valid"),
                Err(err) => Response::error(err, 401),
            }
        })
        .post_async("/signin", |mut req, ctx| async move {
            // Get the json data from the request and set up our access to the KV store where
            // we have all the users
            let json_user: User = req.json().await?;
            let kvstore = ctx.kv("WEBM_AUTH")?;
            // Get the stored account string (if it exists) and then decode it into a record
            // that we can use to compare against what we were given
            let account_string = match kvstore.get(&json_user.username).await? {
                Some(account) => account.as_string(),
                None => {
                    return Response::error(
                        format!("Requested username {} not found", &json_user.username),
                        401,
                    )
                }
            };
            let mut account: user::UserRecord = serde_json::from_str(&account_string.to_owned())?;
            // If the password was successfully updated we can upadte the user record in the
            // KV DB with the record the login function returns
            account =
                user::verify_login(json_user.username.to_owned(), json_user.password, account)?;
            let serialized_record: String = serde_json::to_string(&account)?;

            let serialized_response: String = serde_json::to_string(&UserResponse {
                username: account.username,
                token: account.token,
            })?;
            return match kvstore.put(&json_user.username, &serialized_record) {
                Ok(options) => match options.execute().await {
                    Ok(()) => Response::ok(serialized_response),
                    Err(_) => Response::error(
                        format!("Failed to execute For {}", json_user.username),
                        404,
                    ),
                },
                Err(_) => Response::error(
                    format!("Couldnt Create Options For {}", json_user.username),
                    404,
                ),
            };
        })
        .post_async("/register", |mut req, ctx| async move {
            let json_user: User = req.json().await?;
            let accounts = ctx.kv("WEBM_AUTH")?;
            match accounts.get(&json_user.username).await? {
                Some(_) => return Response::error("User already exists", 401),
                None => (), // We only want to proceed if nothing is found
            };
            let user_rec =
                user::create_user_record(json_user.username.clone(), json_user.password.clone())?;
            let serialized_record: String = match serde_json::to_string(&user_rec) {
                Ok(ser) => ser,
                Err(_) => {
                    return Response::error("Couldn't serialize user record to JSON string", 500)
                }
            };

            let serialized_response: String = match serde_json::to_string(&UserResponse {
                username: user_rec.username,
                token: user_rec.token,
            }) {
                Ok(ser) => ser,
                Err(_) => {
                    return Response::error("Couldn't serialize user record to JSON string", 500)
                }
            };
            return match accounts.put(&json_user.username, &serialized_record) {
                Ok(options) => match options.execute().await {
                    Ok(()) => Response::ok(serialized_response),
                    Err(_) => Response::error(
                        format!("Failed to execute For {}", json_user.username),
                        404,
                    ),
                },
                Err(_) => Response::error(
                    format!("Couldnt Create Options For {}", json_user.username),
                    404,
                ),
            };
        })
        .run(req, env)
        .await
}
