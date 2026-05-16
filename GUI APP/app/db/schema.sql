CREATE TABLE IF NOT EXISTS users (
    username text,
    description text,
    groups text,
    pwdLastSet text,
    machineAccountQuota text,
    ntlmHash text,
    kerberosHash text,
    asrepHash text,
    password text,
    lastSet timestamp
);

CREATE TABLE IF NOT EXISTS profiles (
    name text primary key,
    username text,
    password text,
    domain text,
    dc_ip text,
    dc_fqdn text,
    profile_description text
);

CREATE TABLE IF NOT EXISTS app_state (
    key text primary key,
    value text
);

CREATE TABLE IF NOT EXISTS domain_admins (
    member text,
    collected_at timestamp
);