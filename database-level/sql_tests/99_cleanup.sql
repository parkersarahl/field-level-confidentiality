-- 99_cleanup.sql: removes the helper schema created by 00_setup_helpers.sql. Your data is untouched.
reset role;

drop schema if exists dbtest cascade;

select 'helpers removed' as status;
