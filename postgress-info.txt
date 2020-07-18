# log into user postgres
psql -h localhost -U postgres

# locate db directory
show data_directory;

# exit
\q

# reload
pg_ctl reload -D "the db directory"

# create user
createuser -U postgres -s lobby_user

# superuser privileges
ALTER USER lobby_db WITH SUPERUSER;
GRANT CONNECT ON DATABASE lobby_db TO lobby_user;

# check users-privileges
\du
