-- ======================================================================
-- WordPress wp_users Table Recovery SQL
-- ======================================================================
-- Generated: 2026-01-20 16:23:28
-- Source: wp_users.ibd
-- ======================================================================


CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_activation_key` varchar(255) NOT NULL DEFAULT '',
  `user_status` int(11) NOT NULL DEFAULT '0',
  `display_name` varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`),
  KEY `user_nicename` (`user_nicename`),
  KEY `user_email` (`user_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Recovered user data
INSERT INTO `wp_users` (
  `ID`,
  `user_login`,
  `user_pass`,
  `user_nicename`,
  `user_email`,
  `user_url`,
  `user_registered`,
  `user_activation_key`,
  `user_status`,
  `display_name`
) VALUES (
  1,
  'zemkaart_art',
  '$P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h.',
  'zemkaart_art',
  'CBkFsD3vAH8sFcTDlk5h.zemkaart_artmelisa@digital2.bahttps',
  'https://zemkaart.ba',
  NOW(),
  '',
  0,
  'zemkaart_art'
);

INSERT INTO `wp_users` (
  `ID`,
  `user_login`,
  `user_pass`,
  `user_nicename`,
  `user_email`,
  `user_url`,
  `user_registered`,
  `user_activation_key`,
  `user_status`,
  `display_name`
) VALUES (
  1,
  '',
  '',
  '',
  'melisa@digital2.ba',
  '',
  NOW(),
  '',
  0,
  ''
);


-- ======================================================================
-- RECOVERY NOTES:
-- ======================================================================
-- Total records recovered: 2
-- Some data may be incomplete due to binary file structure
-- Timestamps may need to be updated manually
-- Passwords hashes are recovered but passwords cannot be decrypted
-- ======================================================================