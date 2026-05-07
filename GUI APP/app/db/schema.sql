DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS profiles;

CREATE TABLE users (
    username text;
    description text;
    group text;
    ntlmHash text;
    kerberosHash text;
    asrepHash text;
    password text;
    lastSet timestamp;
);

CREATE TABLE profiles (
    description text;
    name text;
    password text;
    ntlmHash text;
    domain text;
    dc_ip text;
    fqdn text;
);