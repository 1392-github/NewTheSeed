insert into doc_name (name, history_seq)
select "{0}", 1
where not exists (
	select *
	from doc_name
	where name = "{0}"
);
insert into history
values(
	(
		select id
		from doc_name
		where name = "{0}"
		),
	(
		select history_seq
		from doc_name
		where name = "{0}"
		),
	{2},
	"{1}",
	{3},
	{4},
	"{5}",
	{6}
);
update doc_name
set history_seq = (
		select history_seq + 1
		from doc_name
		where name = "{0}"
		)
where name = "{0}";