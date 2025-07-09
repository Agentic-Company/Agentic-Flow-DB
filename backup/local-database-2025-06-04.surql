-- ------------------------------
-- OPTION
-- ------------------------------

OPTION IMPORT;

-- ------------------------------
-- ACCESSES
-- ------------------------------

DEFINE ACCESS user ON DATABASE TYPE RECORD SIGNUP (CREATE user CONTENT { email: $email, name: $name, password: crypto::argon2::generate($password) }) SIGNIN (SELECT * FROM user WHERE email = $email AND crypto::argon2::compare(password, $password)) WITH JWT ALGORITHM HS512 KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' WITH ISSUER KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' AUTHENTICATE {
IF !$auth.enabled { THROW 'This user is not enabled'; };
RETURN $auth;
} DURATION FOR TOKEN 1d, FOR SESSION 1d;

-- ------------------------------
-- TABLE: user
-- ------------------------------

DEFINE TABLE user TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE id = $auth.id, FOR create NONE;

DEFINE FIELD email ON user TYPE string ASSERT string::is::email($value) PERMISSIONS FULL;
DEFINE FIELD enabled ON user TYPE bool VALUE true PERMISSIONS FULL;
DEFINE FIELD name ON user TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD password ON user TYPE string PERMISSIONS FULL;

DEFINE INDEX email_index ON user FIELDS email UNIQUE;


-- ------------------------------
-- TABLE: workflow
-- ------------------------------

DEFINE TABLE workflow TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select WHERE visibility = 'public' OR userId = $auth.id, FOR create WHERE $auth.id != NONE, FOR update, delete WHERE userId = $auth.id;

DEFINE FIELD createdDate ON workflow TYPE datetime VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD description ON workflow TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD edges ON workflow FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD edges[*] ON workflow FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD id ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD lastModified ON workflow TYPE datetime VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD name ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD nodes ON workflow FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD nodes[*] ON workflow FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD status ON workflow TYPE string VALUE 'draft' ASSERT $value INSIDE ['active', 'inactive', 'draft', 'error'] PERMISSIONS FULL;
DEFINE FIELD tags ON workflow TYPE option<array<string>> PERMISSIONS FULL;
DEFINE FIELD tags[*] ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD userId ON workflow TYPE record<user> DEFAULT $auth.id PERMISSIONS FULL;
DEFINE FIELD visibility ON workflow TYPE string VALUE 'private' ASSERT $value INSIDE ['private', 'public'] PERMISSIONS FULL;

DEFINE INDEX idx_workflow_status ON workflow FIELDS status;
DEFINE INDEX idx_workflow_visibility ON workflow FIELDS visibility;


