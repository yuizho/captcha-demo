-- アプリ起動時に schema.sql の後で自動実行される初期データ
insert into users (username, password, enabled) values ('user1', '{noop}password', true);
insert into authorities (username, authority) values ('user1', 'ROLE_USER');
