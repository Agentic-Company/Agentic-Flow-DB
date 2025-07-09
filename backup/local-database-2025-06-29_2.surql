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
-- TABLE: credential
-- ------------------------------

DEFINE TABLE credential TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE userId = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD authType ON credential TYPE string VALUE 'Basic Auth' ASSERT $value INSIDE ['Basic Auth', 'Bearer Token', 'JWT Bearer'] PERMISSIONS FULL;
DEFINE FIELD createdDate ON credential TYPE datetime VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD description ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD id ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD jwtToken ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD lastModified ON credential TYPE datetime VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD name ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD password ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD tags ON credential TYPE option<array<string>> PERMISSIONS FULL;
DEFINE FIELD tags[*] ON credential TYPE string PERMISSIONS FULL;
DEFINE FIELD token ON credential TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD userId ON credential TYPE record<user> DEFAULT $auth.id PERMISSIONS FULL;
DEFINE FIELD username ON credential TYPE option<string> PERMISSIONS FULL;

DEFINE INDEX idx_credential_id ON credential FIELDS id;
DEFINE INDEX idx_credential_name ON credential FIELDS name;


-- ------------------------------
-- TABLE DATA: credential
-- ------------------------------


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
-- TABLE DATA: user
-- ------------------------------

INSERT [ { email: 'dannickstark@gmail.com', enabled: true, id: user:yylag9gnuqyk48v1q86a, password: '$argon2id$v=19$m=19456,t=2,p=1$Q8EGDzNT0n1m/PDh9aAz5w$g5Ur3gbioA+nH+C+9EqH3c6xRWzbCEvzu9cq2MITVi4' } ];

-- ------------------------------
-- TABLE: workflow
-- ------------------------------

DEFINE TABLE workflow TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select WHERE visibility = 'public' OR userId = $auth.id, FOR create WHERE $auth.id != NONE, FOR update, delete WHERE userId = $auth.id;

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
-- TABLE DATA: workflow
-- ------------------------------

INSERT [ { createdDate: d'2025-06-23T23:20:35.479032255Z', edges: [{ id: 'xy-edge__46449c28-511f-485b-a93d-afb02b5e7682-0105bfbb-b60e-4a65-8689-f9dca48ab4e8', source: '46449c28-511f-485b-a93d-afb02b5e7682', target: '0105bfbb-b60e-4a65-8689-f9dca48ab4e8' }, { id: 'xy-edge__0105bfbb-b60e-4a65-8689-f9dca48ab4e8-dc86702e-e5a9-4238-b669-b70acdc0f854', source: '0105bfbb-b60e-4a65-8689-f9dca48ab4e8', target: 'dc86702e-e5a9-4238-b669-b70acdc0f854' }, { id: 'xy-edge__dc86702e-e5a9-4238-b669-b70acdc0f854-4476e1df-e1c2-4c8c-8fc8-8bb6db27b848', source: 'dc86702e-e5a9-4238-b669-b70acdc0f854', target: '4476e1df-e1c2-4c8c-8fc8-8bb6db27b848' }, { id: 'xy-edge__46449c28-511f-485b-a93d-afb02b5e7682-b1cc4360-beb3-4318-bd62-1e7482043959', source: '46449c28-511f-485b-a93d-afb02b5e7682', target: 'b1cc4360-beb3-4318-bd62-1e7482043959' }, { id: 'xy-edge__46449c28-511f-485b-a93d-afb02b5e7682-8dd225af-e47c-4000-aed5-132f8b217e00', source: '46449c28-511f-485b-a93d-afb02b5e7682', target: '8dd225af-e47c-4000-aed5-132f8b217e00' }, { id: 'xy-edge__46449c28-511f-485b-a93d-afb02b5e7682-6be51ccc-449c-4530-8e0d-31d58a31d8c3', source: '46449c28-511f-485b-a93d-afb02b5e7682', target: '6be51ccc-449c-4530-8e0d-31d58a31d8c3' }, { id: 'xy-edge__46449c28-511f-485b-a93d-afb02b5e7682-cfc7b9c8-48bf-4801-914d-a86afd544e88', source: '46449c28-511f-485b-a93d-afb02b5e7682', target: 'cfc7b9c8-48bf-4801-914d-a86afd544e88' }], id: workflow:f30pt5uh2m3km6dqdzp8, lastModified: d'2025-06-23T23:20:35.479057130Z', name: 'ppp (copy)', nodes: [{ data: { failed: false, instance: { id: 'af-base-node:manual:whenStarted' }, isRunning: false, label: 'trigger1', runned: false }, id: '46449c28-511f-485b-a93d-afb02b5e7682', position: { x: -55, y: -35 }, type: 'trigger' }, { data: { failed: false, inputs: { method: 'GET', options: { response: { includeResponseHeaderAndStatus: true } }, url: 'https://dummyjson.com/recipes' }, instance: { id: 'af-base-node:dataTransformation:httpRequest' }, isRunning: false, label: 'Get', runned: false }, id: '0105bfbb-b60e-4a65-8689-f9dca48ab4e8', position: { x: 60, y: -35 }, type: 'basic' }, { data: { failed: false, inputs: { fields: { input1: 'kklk', input2: 'nnnn' } }, instance: { id: 'af-base-node:dataTransformation:editFields' }, isRunning: false, label: 'basic3', runned: false }, id: '4476e1df-e1c2-4c8c-8fc8-8bb6db27b848', position: { x: 320, y: -35 }, type: 'basic' }, { data: { failed: false, inputs: { fieldPath: 'data.recipes' }, instance: { id: 'af-base-node:dataTransformation:pickField' }, isRunning: false, label: 'basic4', runned: false }, id: 'dc86702e-e5a9-4238-b669-b70acdc0f854', position: { x: 195, y: -35 }, type: 'basic' }, { data: { failed: false, inputs: { body: { bodyContent: { body: 'bar', title: 'testing', userId: 1 }, bodyContentType: 'application/json' }, method: 'POST', url: 'https://jsonplaceholder.typicode.com/posts' }, instance: { id: 'af-base-node:dataTransformation:httpRequest' }, isRunning: false, label: 'Post', runned: false }, id: 'b1cc4360-beb3-4318-bd62-1e7482043959', position: { x: 60, y: -140 }, type: 'basic' }, { data: { failed: false, inputs: { body: { bodyContent: { body: 'bar', title: 'foo', userId: '55' } }, method: 'PUT', url: 'https://jsonplaceholder.typicode.com/posts/1' }, instance: { id: 'af-base-node:dataTransformation:httpRequest' }, isRunning: false, label: 'Put', runned: false }, id: '8dd225af-e47c-4000-aed5-132f8b217e00', position: { x: 60, y: 75 }, type: 'basic' }, { data: { failed: false, inputs: { options: { timeout: 1000 }, queryParams: { delay: '2000', q: 'phone' }, url: 'https://dummyjson.com/products/search' }, instance: { id: 'af-base-node:dataTransformation:httpRequest' }, isRunning: false, label: 'Get With Params', runned: false }, id: '6be51ccc-449c-4530-8e0d-31d58a31d8c3', position: { x: 60, y: -245 }, type: 'basic' }, { data: { failed: false, inputs: { body: { bodyContent: { body: 'bar', title: 'foo', userId: '55' } }, method: 'PUT', url: 'https://jsonplaceholder.typicode.com/posts/1' }, instance: { id: 'af-base-node:dataTransformation:httpRequest' }, isRunning: false, label: 'Redirect', runned: false }, id: 'cfc7b9c8-48bf-4801-914d-a86afd544e88', position: { x: 85, y: 175 }, type: 'basic' }], status: 'draft', userId: user:yylag9gnuqyk48v1q86a, visibility: 'private' }, { createdDate: d'2025-06-23T14:31:53.203754635Z', edges: [], id: workflow:jar7vx8zvcaik6z1ltee, lastModified: d'2025-06-23T14:31:53.203768927Z', name: 'ppp', nodes: [{ data: { failed: false, instance: { id: 'af-base-node:manual:whenStarted' }, isRunning: false, label: 'trigger1', runned: false }, id: '46449c28-511f-485b-a93d-afb02b5e7682', measured: { height: 50, width: 50 }, origin: [0.5f, 0], position: { x: 0, y: 0 }, type: 'trigger' }], status: 'draft', userId: user:yylag9gnuqyk48v1q86a, visibility: 'private' } ];

