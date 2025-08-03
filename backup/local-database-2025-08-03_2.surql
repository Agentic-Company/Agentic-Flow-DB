-- ------------------------------
-- OPTION
-- ------------------------------

OPTION IMPORT;

-- ------------------------------
-- ACCESSES
-- ------------------------------

DEFINE ACCESS better_auth ON DATABASE TYPE JWT URL 'http://localhost:8787/auth/jwks' DURATION FOR SESSION NONE;
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
-- TABLE DATA: UserSettings
-- ------------------------------

