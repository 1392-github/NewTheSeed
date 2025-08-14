insert into doc_name (name, history_seq)
select ?1, 1
where not exists (
	select *
	from doc_name
	where name = ?1
);
insert into history
values(
	(
		select id
		from doc_name
		where name = ?1
		),
	(
		select history_seq
		from doc_name
		where name = ?1
		),
	?3,
	?2,
	?4,
	?5,
	?6,
	?7
);
update doc_name
set history_seq = (
		select history_seq + 1
		from doc_name
		where name = ?1
		)
where name = ?1;