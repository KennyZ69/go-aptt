-- It already creates the database from the dockerfile

CREATE TABLE IF NOT EXISTS users(
	user_id SERIAL PRIMARY KEY,
	username VARCHAR(50) ,
	password_hash VARCHAR(255) ,
	email VARCHAR(255) 
)
