CREATE TABLE users (
    id bigserial not null primary key,
    email varchar not null unique,
    username varchar,
    surname varchar,
    patronymic varchar,
    encrypted_password varchar not null
);