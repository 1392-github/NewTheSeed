delete from history
where doc_id = (
	select id
	from doc_name
	where name = "{0}"
);
delete from doc_name
where name = "{0}"