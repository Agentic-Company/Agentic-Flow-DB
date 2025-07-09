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
-- TABLE: Plan
-- ------------------------------

DEFINE TABLE Plan TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select FULL, FOR create, update WHERE NONE, FOR delete NONE;

DEFINE FIELD description ON Plan TYPE string PERMISSIONS FULL;
DEFINE FIELD features ON Plan TYPE array<string> PERMISSIONS FULL;
DEFINE FIELD features[*] ON Plan TYPE string PERMISSIONS FULL;
DEFINE FIELD limits ON Plan TYPE object PERMISSIONS FULL;
DEFINE FIELD name ON Plan TYPE string VALUE Free PERMISSIONS FULL;
DEFINE FIELD price_monthly ON Plan TYPE decimal PERMISSIONS FULL;
DEFINE FIELD price_yearly ON Plan TYPE decimal PERMISSIONS FULL;



-- ------------------------------
-- TABLE: Subscription
-- ------------------------------

DEFINE TABLE Subscription TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;

DEFINE FIELD billing_cycle ON Subscription ASSERT $value INSIDE ['monthly', 'yearly'] PERMISSIONS FULL;
DEFINE FIELD end_date ON Subscription TYPE option<datetime> PERMISSIONS FULL;
DEFINE FIELD plan ON Subscription TYPE record<Plan> PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD start_date ON Subscription TYPE datetime VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD status ON Subscription TYPE string ASSERT $value INSIDE ['active', 'cancelled', 'expired'] PERMISSIONS FULL;
DEFINE FIELD user ON Subscription TYPE record<user> PERMISSIONS FOR select, create FULL, FOR update NONE;



-- ------------------------------
-- TABLE: credential
-- ------------------------------

DEFINE TABLE credential TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE userId = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD authType ON credential TYPE string DEFAULT 'Basic Auth' ASSERT $value INSIDE ['Basic Auth', 'Bearer Token', 'JWT Bearer'] PERMISSIONS FULL;
DEFINE FIELD createdDate ON credential TYPE datetime READONLY VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD description ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD id ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD jwtToken ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD lastModified ON credential TYPE datetime READONLY VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD name ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD password ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD tags ON credential TYPE option<array<string>> PERMISSIONS FULL;
DEFINE FIELD tags[*] ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD token ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD userId ON credential TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FULL;
DEFINE FIELD username ON credential TYPE option<string> PERMISSIONS FULL;

DEFINE INDEX idx_credential_id ON credential FIELDS id;
DEFINE INDEX idx_credential_name ON credential FIELDS name;


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

DEFINE FIELD active_graph ON workflow TYPE option<record<workflowGraph>> PERMISSIONS FULL;
DEFINE FIELD createdDate ON workflow TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD description ON workflow TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD edges ON workflow FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD edges[*] ON workflow FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD id ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD lastModified ON workflow TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD name ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD nodes ON workflow FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD nodes[*] ON workflow FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD status ON workflow TYPE string VALUE 'draft' ASSERT $value INSIDE ['active', 'inactive', 'draft', 'error'] PERMISSIONS FULL;
DEFINE FIELD tags ON workflow TYPE option<array<string>> PERMISSIONS FULL;
DEFINE FIELD tags[*] ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD userId ON workflow TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD visibility ON workflow TYPE string VALUE 'private' ASSERT $value INSIDE ['private', 'public'] PERMISSIONS FULL;

DEFINE INDEX idx_workflow_status ON workflow FIELDS status;
DEFINE INDEX idx_workflow_visibility ON workflow FIELDS visibility;


-- ------------------------------
-- TABLE: workflowGraph
-- ------------------------------

DEFINE TABLE workflowGraph TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE userId = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD createdDate ON workflowGraph TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD edges ON workflowGraph FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD edges[*] ON workflowGraph FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD nodes ON workflowGraph FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD nodes[*] ON workflowGraph FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD userId ON workflowGraph TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD workflowId ON workflowGraph TYPE record<workflow> READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;



