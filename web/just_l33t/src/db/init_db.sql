USE just_l33t_db;

CREATE TABLE `user`(
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(200) NOT NULL,
    `password_hash` CHAR(64) NOT NULL,
    `salt` CHAR(10),
    `is_admin` BOOLEAN NOT NULL DEFAULT FALSE,

    PRIMARY KEY (`id`)
);

CREATE TABLE `item`(
    `id` INT NOT NULL AUTO_INCREMENT,
    `name_en` VARCHAR(200) NOT NULL,
    `name_to` VARCHAR(200) NOT NULL,
    `tag` VARCHAR(200) NOT NULL,
    `price` DECIMAL(10,2) NOT NULL,

    PRIMARY KEY (`id`)
);

CREATE TABLE `order`(
    `id` INT NOT NULL AUTO_INCREMENT,
    `tip` DECIMAL(4, 2) NULL,

    `user_id` INT NOT NULL,

    PRIMARY KEY (`id`),
    FOREIGN KEY (`user_id`) REFERENCES `user`(`id`)
);

CREATE TABLE `order_item`(
    `order_id` INT NOT NULL,
    `item_id` INT NOT NULL,
    `quantity` INT NOT NULL,

    PRIMARY KEY (`order_id`, `item_id`),
    FOREIGN KEY (`order_id`) REFERENCES `order`(`id`),
    FOREIGN KEY (`item_id`) REFERENCES `item`(`id`)
);

CREATE TABLE `cookie`(
    `id` CHAR(32) NOT NULL,
    `cookies` VARCHAR(2000) NOT NULL,
    `user_id` INT NOT NULL,

    PRIMARY KEY (`id`),
    FOREIGN KEY (`user_id`) REFERENCES `user`(`id`)
);

INSERT INTO user VALUES
    (DEFAULT, 'admin', '8fa739341a60b677d3c85f42c469f5115344115549dfe84494f25a1446b489d9', 'eOvmaxkU7A', TRUE);

INSERT INTO item VALUES 
    (DEFAULT, 'Kebab from Hassan', 'Kebab di Hassan', 'kebab', 5.00),
    (DEFAULT, 'Carbonara from the chinese-roman guy', 'Harbonara de i cinoromano', 'other', 5.50),
    (DEFAULT, 'Pizza from Dabbe', "La stiacciata co' i pomodoro", 'pizza', 12.00),
    (DEFAULT, 'Schiacciata from Antico Vinaio', 'Bada home la fuma', 'pizza', 7.00),
    (DEFAULT, 'Falafel from Al Medina', 'Falafel di Medina', 'kebab', 7.00),
    (DEFAULT, 'Sgabeo Dario Moccia', "Deh pefforza, deh", 'other', 4.50),
    (DEFAULT, 'Pisean style pizza from Bagni di Nerone', "Pizza che fa ca'", 'pizza', 8.00);
