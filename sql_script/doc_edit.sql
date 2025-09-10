insert into history
values(
	?1,
	(
		select history_seq
		from doc_name
		where id = ?1
		),
	?3,
	?2,
	?4,
	?5,
	?6,
	?7
);
update doc_name
set history_seq = history_seq + 1
where id = ?1;