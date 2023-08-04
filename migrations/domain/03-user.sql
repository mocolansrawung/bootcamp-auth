DROP TABLE IF EXISTS `users`;

CREATE TABLE users (
    id CHAR(36) NOT NULL,
    username CHAR(36) UNIQUE,
    name VARCHAR(255),
    password CHAR(60),
    role ENUM('teacher', 'student'),
    created_at DATETIME NOT NULL,
    created_by CHAR(36) NOT NULL,
    updated_at DATETIME,
    updated_by CHAR(36),
    deleted_at DATETIME,
    deleted_by CHAR(36),
    PRIMARY KEY (id)
) ENGINE=InnoDB
DEFAULT CHARSET=utf8;