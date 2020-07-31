use data_encoding::HEXUPPER;
use rand;
use ring::error::Unspecified;
use ring::{digest, pbkdf2};
use rusqlite::NO_PARAMS;
use rusqlite::{named_params, params, Connection};
use std::error::Error;
use std::fmt;

// User Struct
pub struct User {
    pub name: String,
    pub salt: String,
    pub hash: String,
    pub active: bool,
}

// Constants
const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
const N_ITER: u32 = 100_000;

// Error Used for User related Functions
// Implements the traits of Error
#[derive(Debug)]
struct UserError(String);
impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for UserError {}

// Generates a salt
fn get_salt() -> Vec<u8> {
    let salt: Vec<u8> = (0..CREDENTIAL_LEN).map(|_| rand::random::<u8>()).collect();
    salt
}

// Takes in a salt and password and returns the hash
// using the pbkdf2 algorithm
fn get_hash_from_password(password: String, salt: Vec<u8>) -> Vec<u8> {
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        &digest::SHA512,
        N_ITER,
        &salt,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );
    pbkdf2_hash.to_vec()
}

// Verifies a password and salt against a hash
// using the pbkdf2 algorithm
fn verify_password(
    password: String,
    salt: Vec<u8>,
    pbkdf2_hash: Vec<u8>,
) -> Result<(), Unspecified> {
    pbkdf2::verify(
        &digest::SHA512,
        N_ITER,
        &salt,
        password.as_bytes(),
        &pbkdf2_hash,
    )
}

// creates a sqlite DB if it does not exist and initializes the user table
// returns the connection
fn connection() -> Result<rusqlite::Connection, Box<dyn Error>> {
    let conn = Connection::open("sqlite.db").expect("db conn fail");

    // create the users table if it does not exist
    match conn.execute(
        "create table if not exists users (
             id integer primary key,
             name text not null unique,
             salt text not null,
             hash text not null,
             active integer default 1 not null
         );",
        NO_PARAMS,
    ) {
        Ok(_) => {
            return Ok(conn);
        }
        Err(_) => {
            return Err(Box::new(UserError("Error Creating table".into())));
        }
    };
}

impl User {
    // trait used to create a user
    pub fn create(&mut self, password: String) -> Result<(), Box<dyn Error>> {
        // Generates a salt for the user
        let salt = get_salt();
        self.salt = HEXUPPER.encode(&salt);
        // Generates a hash from the salt and password
        let hash = get_hash_from_password(password, salt);
        self.hash = HEXUPPER.encode(&hash);
        // Connect to the db
        match connection() {
            Ok(conn) => {
                // Insert User into the db
                match conn.execute(
                    "INSERT INTO users (name, salt, hash, active) VALUES (?1, ?2, ?3, ?4)",
                    params![self.name, self.salt, self.hash, self.active as i32],
                ) {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(_) => {
                        // There was an error inserting the user
                        return Err(Box::new(UserError("Error Creating User".into())));
                    }
                }
            }
            _ => {
                // Connection Error
                return Err(Box::new(UserError("Connection Error".into())));
            }
        }
    }
    // Trait to Authorize the User
    pub fn authorize(&mut self, password: String) -> Result<(), Box<dyn Error>> {
        // Connect to DB
        match connection() {
            Ok(conn) => {
                // Prepare Select statement
                let mut stmt = conn
                    .prepare("SELECT id, name, salt, hash, active FROM users WHERE name = :name LIMIT 1;")
                    .expect("");
                // Run the Query Passing in the user name
                let mut rows = stmt
                    .query_named(named_params! { ":name": self.name })
                    .expect("");
                // Iterate over results (Should only ever return one)
                while let Some(row) = rows.next().expect("") {
                    // Set Salt from DB
                    self.salt = row.get(2)?;
                    // Set Hash From DB
                    self.hash = row.get(3)?;
                    // Set Active From DB
                    let active: i32 = row.get(4)?;
                    self.active = active != 0;
                }
                // Decode Hash into bytes
                let hash = HEXUPPER
                    .decode(self.hash.as_bytes())
                    .expect("Error Decoding Hash");
                // Decode Salt into bytes
                let salt = HEXUPPER
                    .decode(self.salt.as_bytes())
                    .expect("Error Decoding Salt");
                // Verify Password against hash using salt
                match verify_password(password, salt, hash) {
                    Ok(()) => {
                        return Ok(());
                    }
                    Err(_) => {
                        return Err(Box::new(UserError("Invalid User".into())));
                    }
                }
            }
            _ => return Err(Box::new(UserError("DB Connection Error".into()))),
        };
    }

    // TODO: Implement update feature
    // pub fn update(&mut self) {}

    // TODO: Implement Delete Feature
    // pub fn delete(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::User;
    use super::{get_hash_from_password, get_salt, verify_password};
    use ring::digest;
    use std::fs;

    #[test]
    fn test_get_salt() {
        let salt = get_salt();
        assert!(
            salt.len() == digest::SHA512_OUTPUT_LEN,
            "Expected Salt to be of length {} but got {}",
            digest::SHA512_OUTPUT_LEN,
            salt.len()
        )
    }

    #[test]
    fn test_hashing_password() {
        let salt = get_salt();
        let hash = get_hash_from_password(String::from("Password1"), salt.clone());
        let verify_correct_password =
            verify_password(String::from("Password1"), salt.clone(), hash.clone());
        let verify_incorrect_password = verify_password(String::from("Password2"), salt, hash);
        assert!(
            verify_correct_password.is_ok(),
            "Expected password to get verified"
        );
        assert!(
            !verify_incorrect_password.is_ok(),
            "Expected password to fail verification"
        )
    }

    #[test]
    fn test_create_and_get() {
        let mut user = User {
            name: "spazzy".to_string(),
            salt: "".to_string(),
            hash: "".to_string(),
            active: true,
        };
        assert!(
            user.create(String::from("Password1")).is_ok(),
            "Failed Creating User"
        );

        user = User {
            name: String::from("spazzy"),
            salt: String::from(""),
            hash: String::from(""),
            active: false,
        };

        assert!(
            user.authorize(String::from("Password1")).is_ok(),
            "Failed Authenticating User"
        );
        // Clean up the DB after tests have run
        assert!(
            fs::remove_file("sqlite.db").is_ok(),
            "Failed Removing Database"
        );
    }
}
