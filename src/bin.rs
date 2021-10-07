extern crate dotenv;
extern crate twitter_api;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use twitter_api::SigningKey;
use twitter_api::TwitterApi;

fn main() -> Result<()> {
    dotenv::from_filename(".env").ok();

    let tweety = TwitterApi::new(
        &env::var("CONSUMER_KEY")?,
        &env::var("TOKEN")?,
        SigningKey::new(&env::var("CONSUMER_SECRET")?, &env::var("TOKEN_SECRET")?),
    );

    // println!("{:?}", tweety.tweet("Lol"));
    Ok(())
}
