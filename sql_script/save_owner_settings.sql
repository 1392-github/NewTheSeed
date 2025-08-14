update config
set value = ?1
where name = "host";
update config
set value = ?2
where name = "port";
update config
set value = ?3
where name = "owner";
update config
set value = ?4
where name = "debug";
update config
set value = ?5
where name = "get_api_key";