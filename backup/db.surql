DEFINE TABLE OVERWRITE user SCHEMAFULL
	PERMISSIONS
		FOR select, update, delete WHERE id = $auth.id;

DEFINE FIELD name ON user TYPE option<string>;
DEFINE FIELD email ON user TYPE string ASSERT string::is::email($value);
DEFINE FIELD password ON user TYPE string;
DEFINE FIELD enabled ON user TYPE bool
    VALUE true;

DEFINE INDEX email_index ON user FIELDS email UNIQUE;






--------------------------------
DEFINE ACCESS OVERWRITE user ON DATABASE TYPE RECORD SIGNUP (CREATE user CONTENT {
	email: $email,
	name: $name,
	password: crypto::argon2::generate($password)
}) SIGNIN (SELECT * FROM user WHERE email = $email AND crypto::argon2::compare(password, $password)) WITH JWT ALGORITHM HS512 KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' WITH ISSUER KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' AUTHENTICATE {

	IF !$auth.enabled
		{
			THROW 'This user is not enabled';
		}
	;

	RETURN $auth;

} DURATION FOR TOKEN 1d, FOR SESSION 1d;





--------------------------------
DEFINE TABLE workflow SCHEMAFULL
    -- Define permissions (adjust according to your needs)
    PERMISSIONS
        FOR select
            WHERE visibility = 'public' OR userId = $auth.id
        FOR create
            WHERE $auth.id != NONE
        FOR update
            WHERE userId = $auth.id
        FOR delete
            WHERE userId = $auth.id;

-- Required fields
DEFINE FIELD id ON workflow TYPE string;
DEFINE FIELD userId ON workflow TYPE record<user>;
DEFINE FIELD name ON workflow TYPE string;

-- Fields with default values
DEFINE FIELD status ON workflow TYPE string 
    VALUE 'draft'
    ASSERT $value INSIDE ['active', 'inactive', 'draft', 'error'];

DEFINE FIELD lastModified ON workflow TYPE datetime 
    VALUE time::now();

DEFINE FIELD createdDate ON workflow TYPE datetime 
    VALUE time::now();

DEFINE FIELD visibility ON workflow TYPE string 
    VALUE 'private'
    ASSERT $value INSIDE ['private', 'public'];

-- Optional fields
DEFINE FIELD description ON workflow TYPE option<string>;
DEFINE FIELD tags ON workflow TYPE option<array<string>>;

-- Define indexes for better query performance
DEFINE INDEX idx_workflow_status ON workflow FIELDS status;
DEFINE INDEX idx_workflow_visibility ON workflow FIELDS visibility;