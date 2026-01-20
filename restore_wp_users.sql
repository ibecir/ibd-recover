-- ======================================================================
-- InnoDB Recovery: wp_users
-- ======================================================================
-- Source file: wp_users.ibd
-- File size: 163,840 bytes
-- Recovery date: 2026-01-20 16:55:45
-- Records found: 1
-- ======================================================================

CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_nicename` varchar(50) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_activation_key` varchar(255) NOT NULL DEFAULT '',
  `user_status` int(11) NOT NULL DEFAULT '0',
  `display_name` varchar(250) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`),
  KEY `user_login_key` (`user_login`),
  KEY `user_nicename` (`user_nicename`),
  KEY `user_email` (`user_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- RECOVERED DATA
-- ----------------------------------------------------------------------

INSERT INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`, `user_email`, `user_url`, `user_registered`, `user_activation_key`, `user_status`, `display_name`) VALUES (1, 'zemkaart_art', '$P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h.', 'zemkaart_art', 'melisa@digital2.ba', 'https://zemkaart.ba', NOW(), '', 0, 'zemkaart_art');

-- ======================================================================
-- ALL EXTRACTED STRINGS (for manual review)
-- ======================================================================
/*
"
 ,%
!dm
!infimum
${\
&)Z
&pV2
+=
+wwO
+yT
.1y
.[J
/&%
/T$
23
3[W
5DrE2
5R+
7Fs
9h32
;d/7
>y9
@wz
BrL
Csh
Ct)
DG3
F\']
F^QJ
Fow2
J*6
JZ2o
KDf
Kinfimum
O=:
Q_g-j4
R:4
Rptc
RtC
SI1a.Z*
U+y"
X7lk7
Y#^|@
\-yZ
\]o
\y-yeL
_j:
`=F
`LZ
f2?
gm7u
h!J
melisa@digital2.ba
mz/
o//
supremum
tG
xsh?
yG3
yim
zemkaart_art
zemkaart_art$P$BmP6qBlu5/CBkFsD3vAH8sFcTDlk5h.zemkaart_artmelisa@digital2.bahttps://zemkaart.ba
} tf
}bv
}qM
~8Y
*/

-- ======================================================================
-- IMPORTANT:
-- 1. Review all INSERT statements before executing
-- 2. Password hashes recovered - actual passwords CANNOT be decrypted
-- 3. Reset passwords after restoration
-- 4. Some fields may be incomplete - this is normal for binary recovery
-- ======================================================================