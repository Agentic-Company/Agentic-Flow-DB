DEFINE FUNCTION OVERWRITE fn::create_limited_workflow($name: string, $description: option<string>, $tags: option<array<string>>, $status: option<string>, $visibility: option<string>) -> object {
	`BEGIN`;
	LET $data = (SELECT subscription.plan.max_workflows AS limit FROM user WHERE id = $auth.id);
	LET $limit = $data[0].limit;
	IF $limit != NONE AND $limit != math::INF
		{
	
			LET $count = (SELECT count() FROM workflow WHERE usedId = $auth);
	
			IF $count[0].count >= $limit
				{
					THROW 'Workflow limit reached for your current plan.';
				}
			;
		
	}
	;
	LET $created = (CREATE workflow SET name = $name, description = $description, tags = $tags, status = $status, visibility = $visibility);
	`COMMIT`;
	RETURN $created[0];
} PERMISSIONS WHERE $auth.id != NONE