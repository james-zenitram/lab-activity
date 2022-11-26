-- SET FOREIGN_KEY_CHECKS = 0;
-- TRUNCATE TABLE role;
-- TRUNCATE TABLE users;
-- SET FOREIGN_KEY_CHECKS = 1;

-- Roles
INSERT INTO `roles` (`name`) VALUES ('ROLE_PRESIDENT');
INSERT INTO `roles` (`name`) VALUES ('ROLE_DEAN');
INSERT INTO `roles` (`name`) VALUES ('ROLE_STUDENT');

-- President, password = patrick
INSERT INTO `users` (`email`, `full_name`, `password`, `enabled`, `role`, `otp_enabled`, `otp`, `otp_requested_time`)
    VALUES ('martinezjames009@gmail.com', 'James', '$2a$10$IqTJTjn39IU5.7sSCDQxzu3xug6z/LPU6IF0azE/8CkHCwYEnwBX.', '1', '1', '1', NULL, NULL);

-- Professor
INSERT INTO `users` (`email`, `full_name`, `password`, `enabled`, `role`, `otp_enabled`, `otp`, `otp_requested_time`)
    VALUES ('patrick@gmail.com', 'Patrick', '$2a$10$cTUErxQqYVyU2qmQGIktpup5chLEdhD2zpzNEyYqmxrHHJbSNDOG.', '1', '2', '0', NULL, NULL );

-- Student
INSERT INTO `users` (`email`, `full_name`, `password`, `enabled`, `role`, `otp_enabled`, `otp`, `otp_requested_time`)
    VALUES ('alex@gmail.com', 'Alex', '$2a$10$.tP2OH3dEG0zms7vek4ated5AiQ.EGkncii0OpCcGq4bckS9NOULu', '1', '3', '0', NULL, NULL);


