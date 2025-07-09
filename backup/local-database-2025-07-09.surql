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
-- FUNCTIONS
-- ------------------------------

DEFINE FUNCTION fn::create_limited_workflow($name: string, $description: option<string>, $tags: option<array<string>>, $status: option<string>, $visibility: option<string>) -> object {
`BEGIN`;
LET $data = (SELECT current_subscription.plan.limits.max_workflows AS limit FROM user WHERE id = $auth.id);
LET $limit = $data[0].limit;
IF $limit != NONE AND $limit != math::INF {
LET $count = (SELECT count(), userId FROM workflow WHERE userId = $auth.id GROUP BY userId);
IF $count[0].count >= $limit { THROW 'Workflow limit reached for your current plan.'; };
};
LET $created = (CREATE ONLY workflow SET name = $name, description = $description, tags = $tags, status = $status, visibility = $visibility);
`COMMIT`;
RETURN $created;
} PERMISSIONS WHERE $auth.id != NONE;
DEFINE FUNCTION fn::create_limited_workflow_graph($graph: object) -> record<workflowGraph> {
`BEGIN`;
LET $data = (SELECT current_subscription.plan.limits.max_workflow_versions AS limit FROM user WHERE id = $auth.id);
LET $limit = $data[0].limit;
IF $limit != NONE AND $limit != math::INF {
LET $count = (SELECT count(), userId FROM workflow_graph WHERE userId = $auth.id GROUP BY userId);
IF $count[0].count >= $limit { THROW 'WorkflowGraph limit reached for your current plan.'; };
};
LET $created = (CREATE ONLY workflow_graph SET nodes = $graph.nodes, edges = $graph.edges, workflowId = $graph.workflowId);
`COMMIT`;
RETURN $created;
} PERMISSIONS WHERE $auth.id != NONE;

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
-- TABLE DATA: credential
-- ------------------------------

