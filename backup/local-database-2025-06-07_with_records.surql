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

INSERT [ { createdDate: d'2025-06-04T21:03:11.538622136Z', edges: [{ id: 'e1-2', source: '1', target: '2' }, { id: 'xy-edge__0.027664734500083776-1', source: '0.027664734500083776', target: '1' }, { id: 'xy-edge__2-1', source: '2', target: '1' }, { id: 'xy-edge__0.027664734500083776-2', source: '0.027664734500083776', target: '2' }, { id: 'xy-edge__0.7564361818924501-2', source: '0.7564361818924501', target: '2' }], id: workflow:dfwn0xpf7x5qguw5uhvh, lastModified: d'2025-06-04T21:03:11.538626052Z', name: 'Simple AI Flow', nodes: [{ data: { instance: { id: 'af-base-node:other:utility:unknown' }, label: '1' }, id: '1', measured: { height: 50, width: 50 }, position: { x: -40, y: 90 }, selected: false, type: 'basic' }, { data: { instance: { id: 'af-base-node:other:utility:unknown' }, label: '2' }, id: '2', measured: { height: 50, width: 50 }, position: { x: 50, y: -50 }, selected: false, type: 'basic' }, { data: { instance: { id: 'af-base-node:manual:trigger:whenStarted' }, label: 'When the node is started' }, dragging: false, id: '0.027664734500083776', measured: { height: 50, width: 50 }, position: { x: -90, y: -120 }, selected: true, type: 'trigger' }, { data: { instance: { id: 'af-base-node:dataTransformation:action:code' }, label: 'Code' }, id: '0.7564361818924501', measured: { height: 50, width: 50 }, origin: [0.5f, 0], position: { x: -80, y: -30 }, type: 'basic' }], status: 'draft', userId: user:yylag9gnuqyk48v1q86a, visibility: 'private' }, { createdDate: d'2025-06-04T21:03:11.538722261Z', id: workflow:fphdo1s7lj5cdlo68f7c, lastModified: d'2025-06-04T21:03:11.538725177Z', name: 'Simple AI Flow 2', status: 'draft', userId: user:yylag9gnuqyk48v1q86a, visibility: 'private' } ];

