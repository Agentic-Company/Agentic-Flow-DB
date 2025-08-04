-- ------------------------------
-- OPTION
-- ------------------------------

OPTION IMPORT;

-- ------------------------------
-- ACCESSES
-- ------------------------------

DEFINE ACCESS token_auth ON DATABASE TYPE RECORD WITH JWT URL 'http://host.docker.internal:8787/auth/jwks' AUTHENTICATE { IF $auth.id { IF !$auth.enabled { THROW 'This user is not enabled'; } ELSE { RETURN $auth; }; } ELSE IF $token.email { RETURN (SELECT * FROM user WHERE email = $token.email); }; } DURATION FOR TOKEN 1h, FOR SESSION NONE;
DEFINE ACCESS user ON DATABASE TYPE RECORD SIGNUP (CREATE user CONTENT { email: $email, name: $name, password: crypto::argon2::generate($password) }) SIGNIN (SELECT * FROM user WHERE email = $email AND crypto::argon2::compare(password, $password)) WITH JWT ALGORITHM HS512 KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' WITH ISSUER KEY 'sUPLZ6i7jCOtjdLPf7Q1PRUAN9fEPFH892oluiDKtrlsVakk131UNV8mcQbXKWAa2PYCiH3WOtg9GY7VhU01VWRTSQvmSpDzjZQivB9pkmhDDOp8ikm0CDfEcibMbHLe' AUTHENTICATE {
IF !$auth.enabled { THROW 'This user is not enabled'; };
RETURN $auth;
} DURATION FOR TOKEN 1d, FOR SESSION 1d;

-- ------------------------------
-- FUNCTIONS
-- ------------------------------

DEFINE FUNCTION fn::create_limited_execution($execution: object, $logs: array<object>) -> object {
`BEGIN`;
LET $data = (SELECT current_subscription.plan.limits.max_executions AS limit FROM user WHERE id = $auth.id);
LET $limit = $data[0].limit;
IF $limit != NONE AND $limit != math::INF {
LET $count = (SELECT count(), userId FROM execution WHERE workflowId.userId = $auth.id GROUP BY userId);
IF $count[0].count >= $limit {
LET $last = (SELECT id, createdDate FROM execution WHERE workflowId.userId = $auth.id ORDER BY createdDate
 LIMIT 1);
DELETE execution WHERE id = $last[0].id;
};
};
LET $createdExecution = (CREATE ONLY execution SET status = $execution.status, executionDate = $execution.executionDate, duration = $execution.duration, workflowId = type::record($execution.workflowId, 'workflow'), workflowGraphId = type::record($execution.workflowGraphId, 'workflowGraph'));
FOR $log IN $logs { CREATE log SET message = $log.message, level = $log.level, timestamp = $log.timestamp, executionId = type::record($createdExecution.id, 'execution'); };
`COMMIT`;
RETURN $createdExecution;
} PERMISSIONS WHERE $auth.id != NONE;
DEFINE FUNCTION fn::create_limited_workflow($workflow: object) -> object {
`BEGIN`;
LET $data = (SELECT current_subscription.plan.limits.max_workflows AS limit FROM user WHERE id = $auth.id);
LET $limit = $data[0].limit;
IF $limit != NONE AND $limit != math::INF {
LET $count = (SELECT count(), userId FROM workflow WHERE userId = $auth.id GROUP BY userId);
IF $count[0].count >= $limit { THROW 'Workflow limit reached for your current plan.'; };
};
LET $created = (CREATE ONLY workflow SET name = $workflow.name, description = $workflow.description, tags = $workflow.tags, status = $workflow.status, visibility = $workflow.visibility, type = $workflow.type);
`COMMIT`;
RETURN $created;
} PERMISSIONS WHERE $auth.id != NONE;
DEFINE FUNCTION fn::create_limited_workflow_graph($graph: object) -> object {
`BEGIN`;
LET $data = (SELECT current_subscription.plan.limits.max_workflow_versions AS limit FROM user WHERE id = $auth.id);
LET $limit = $data[0].limit;
IF $limit != NONE AND $limit != math::INF {
LET $count = (SELECT count(), userId FROM workflowGraph WHERE userId = $auth.id GROUP BY userId);
IF $count[0].count >= $limit {
LET $last = (SELECT id, createdDate FROM workflowGraph WHERE userId = $auth.id ORDER BY createdDate
 LIMIT 1);
DELETE workflowGraph WHERE id = $last[0].id;
};
};
LET $createdGraph = (CREATE ONLY workflowGraph SET nodes = $graph.nodes, edges = $graph.edges, workflowId = type::record($graph.workflowId, 'workflow'));
`COMMIT`;
RETURN $createdGraph;
} PERMISSIONS WHERE $auth.id != NONE;

-- ------------------------------
-- TABLE: UserSettings
-- ------------------------------

DEFINE TABLE UserSettings TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update WHERE userId = $auth.id, FOR create WHERE $auth.id != NONE AND array::len((SELECT * FROM UserSettings WHERE userId = $auth.id)) = 0, FOR delete NONE;

DEFINE FIELD createdDate ON UserSettings TYPE datetime READONLY VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD lastModified ON UserSettings TYPE datetime READONLY VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD profilePicture ON UserSettings TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD userId ON UserSettings TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FULL;
DEFINE FIELD username ON UserSettings TYPE option<string> PERMISSIONS FULL;



-- ------------------------------
-- TABLE: account
-- ------------------------------

DEFINE TABLE account TYPE ANY SCHEMALESS COMMENT 'better-auth: accounts' PERMISSIONS NONE;

DEFINE FIELD accessToken ON account TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD accessTokenExpiresAt ON account TYPE option<datetime> PERMISSIONS FULL;
DEFINE FIELD accountId ON account TYPE string PERMISSIONS FULL;
DEFINE FIELD createdAt ON account TYPE datetime DEFAULT time::now() PERMISSIONS FULL;
DEFINE FIELD idToken ON account TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD password ON account TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD providerId ON account TYPE string PERMISSIONS FULL;
DEFINE FIELD refreshToken ON account TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD refreshTokenExpiresAt ON account TYPE option<datetime> PERMISSIONS FULL;
DEFINE FIELD scope ON account TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD updatedAt ON account TYPE datetime DEFAULT time::now() PERMISSIONS FULL;
DEFINE FIELD userId ON account TYPE record<user> PERMISSIONS FULL;



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
-- TABLE: execution
-- ------------------------------

DEFINE TABLE execution TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE workflowGraphId.workflowId.userId = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD createdDate ON execution TYPE datetime READONLY VALUE time::now() PERMISSIONS FULL;
DEFINE FIELD duration ON execution TYPE number PERMISSIONS FULL;
DEFINE FIELD executionDate ON execution TYPE datetime PERMISSIONS FULL;
DEFINE FIELD status ON execution TYPE string DEFAULT 'success' ASSERT $value INSIDE ['error', 'canceled', 'queued', 'running', 'success', 'waiting'] PERMISSIONS FULL;
DEFINE FIELD workflowGraphId ON execution TYPE record<workflowGraph> PERMISSIONS FULL;
DEFINE FIELD workflowId ON execution TYPE record<workflow> PERMISSIONS FULL;



-- ------------------------------
-- TABLE: jwks
-- ------------------------------

DEFINE TABLE jwks TYPE NORMAL SCHEMALESS PERMISSIONS NONE;

DEFINE FIELD createdAt ON jwks TYPE datetime DEFAULT time::now() READONLY PERMISSIONS FULL;
DEFINE FIELD privateKey ON jwks TYPE string PERMISSIONS FULL;
DEFINE FIELD publicKey ON jwks TYPE string PERMISSIONS FULL;



-- ------------------------------
-- TABLE: log
-- ------------------------------

DEFINE TABLE log TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select FULL, FOR create WHERE $auth.id != NONE, FOR update WHERE NONE, FOR delete NONE;

DEFINE FIELD createdDate ON log TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD executionId ON log TYPE record<execution> PERMISSIONS FULL;
DEFINE FIELD level ON log TYPE string DEFAULT 'simple' ASSERT $value INSIDE ['info', 'warn', 'error', 'simple', 'success'] PERMISSIONS FULL;
DEFINE FIELD message ON log TYPE string PERMISSIONS FULL;
DEFINE FIELD timestamp ON log TYPE datetime PERMISSIONS FULL;



-- ------------------------------
-- TABLE: plan
-- ------------------------------

DEFINE TABLE plan TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select FULL, FOR create, update, delete NONE;

DEFINE FIELD description ON plan TYPE string PERMISSIONS FULL;
DEFINE FIELD limits ON plan FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD name ON plan TYPE string PERMISSIONS FULL;
DEFINE FIELD price_monthly ON plan TYPE decimal PERMISSIONS FULL;
DEFINE FIELD price_yearly ON plan TYPE decimal PERMISSIONS FULL;



-- ------------------------------
-- TABLE: session
-- ------------------------------

DEFINE TABLE session TYPE ANY SCHEMALESS COMMENT 'better-auth: sessions' PERMISSIONS NONE;

DEFINE FIELD createdAt ON session TYPE datetime DEFAULT time::now() PERMISSIONS FULL;
DEFINE FIELD expiresAt ON session TYPE datetime PERMISSIONS FULL;
DEFINE FIELD ipAddress ON session TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD token ON session TYPE string PERMISSIONS FULL;
DEFINE FIELD updatedAt ON session TYPE datetime DEFAULT time::now() PERMISSIONS FULL;
DEFINE FIELD userAgent ON session TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD userId ON session TYPE record<user> PERMISSIONS FULL;



-- ------------------------------
-- TABLE: subscription
-- ------------------------------

DEFINE TABLE subscription TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE user = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD billing_cycle ON subscription TYPE string ASSERT $value INSIDE ['monthly', 'yearly'] PERMISSIONS FULL;
DEFINE FIELD end_date ON subscription TYPE option<datetime> PERMISSIONS FULL;
DEFINE FIELD plan ON subscription TYPE record<plan> PERMISSIONS FULL;
DEFINE FIELD start_date ON subscription TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD status ON subscription TYPE string DEFAULT 'active' ASSERT $value INSIDE ['active', 'cancelled', 'expired'] PERMISSIONS FULL;
DEFINE FIELD user ON subscription TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;



-- ------------------------------
-- TABLE: user
-- ------------------------------

DEFINE TABLE user TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE id = $auth.id, FOR create NONE;

DEFINE FIELD createdAt ON user TYPE datetime DEFAULT time::now() READONLY PERMISSIONS FULL;
DEFINE FIELD current_subscription ON user TYPE option<record<subscription>> PERMISSIONS FULL;
DEFINE FIELD email ON user TYPE string PERMISSIONS FULL;
DEFINE FIELD emailVerified ON user TYPE option<bool> DEFAULT false PERMISSIONS FULL;
DEFINE FIELD enabled ON user TYPE option<bool> DEFAULT true PERMISSIONS FULL;
DEFINE FIELD image ON user TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD name ON user TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD updatedAt ON user TYPE option<datetime> VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;

DEFINE INDEX email_index ON user FIELDS email UNIQUE;


-- ------------------------------
-- TABLE: verification
-- ------------------------------

DEFINE TABLE verification TYPE ANY SCHEMALESS COMMENT 'better-auth: verification' PERMISSIONS NONE;

DEFINE FIELD `value` ON verification TYPE string PERMISSIONS FULL;
DEFINE FIELD createdAt ON verification TYPE datetime DEFAULT time::now() PERMISSIONS FULL;
DEFINE FIELD expiresAt ON verification TYPE datetime PERMISSIONS FULL;
DEFINE FIELD identifier ON verification TYPE string PERMISSIONS FULL;
DEFINE FIELD updatedAt ON verification TYPE datetime DEFAULT time::now() PERMISSIONS FULL;



-- ------------------------------
-- TABLE: workflow
-- ------------------------------

DEFINE TABLE workflow TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select WHERE visibility = 'public' OR userId = $auth.id, FOR create WHERE $auth.id != NONE, FOR update, delete WHERE userId = $auth.id;

DEFINE FIELD active_graph ON workflow TYPE option<record<workflowGraph>> PERMISSIONS FULL;
DEFINE FIELD createdDate ON workflow TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD description ON workflow TYPE option<string> PERMISSIONS FULL;
DEFINE FIELD id ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD lastModified ON workflow TYPE datetime DEFAULT time::now() READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD name ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD status ON workflow TYPE string VALUE 'draft' ASSERT $value INSIDE ['active', 'inactive', 'draft', 'error'] PERMISSIONS FULL;
DEFINE FIELD tags ON workflow TYPE option<array<string>> PERMISSIONS FULL;
DEFINE FIELD tags[*] ON workflow TYPE string PERMISSIONS FULL;
DEFINE FIELD type ON workflow TYPE option<string> DEFAULT 'triggered' ASSERT $value INSIDE ['triggered', 'lambda'] PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD userId ON workflow TYPE record<user> DEFAULT $auth.id READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD visibility ON workflow TYPE string VALUE 'private' ASSERT $value INSIDE ['private', 'public'] PERMISSIONS FULL;

DEFINE INDEX idx_workflow_status ON workflow FIELDS status;
DEFINE INDEX idx_workflow_visibility ON workflow FIELDS visibility;


-- ------------------------------
-- TABLE: workflowGraph
-- ------------------------------

DEFINE TABLE workflowGraph TYPE NORMAL SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE workflowId.userId = $auth.id, FOR create WHERE $auth.id != NONE;

DEFINE FIELD createdDate ON workflowGraph TYPE datetime READONLY VALUE time::now() PERMISSIONS FOR select, create FULL, FOR update NONE;
DEFINE FIELD edges ON workflowGraph FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD edges[*] ON workflowGraph FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD nodes ON workflowGraph FLEXIBLE TYPE option<array<object>> PERMISSIONS FULL;
DEFINE FIELD nodes[*] ON workflowGraph FLEXIBLE TYPE object PERMISSIONS FULL;
DEFINE FIELD workflowId ON workflowGraph TYPE record<workflow> READONLY PERMISSIONS FOR select, create FULL, FOR update NONE;



