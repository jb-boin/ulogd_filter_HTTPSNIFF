SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

DELIMITER $$
--
-- Functions
--
CREATE FUNCTION `BIN_TO_IP` (`_in` BINARY(16)) RETURNS VARCHAR(64) CHARSET utf8 SQL SECURITY INVOKER
    COMMENT 'Convert binary IP to printable string'
BEGIN
		IF HEX(SUBSTRING(_in, 1, 12)) = '00000000000000000000FFFF' THEN
		RETURN CONCAT(
			ASCII(SUBSTRING(_in, 13, 1)), '.',
			ASCII(SUBSTRING(_in, 14, 1)), '.',
			ASCII(SUBSTRING(_in, 15, 1)), '.',
			ASCII(SUBSTRING(_in, 16, 1))
		);
	END IF;
		RETURN LOWER(CONCAT(
		HEX(SUBSTRING(_in, 1, 2)), ':',
		HEX(SUBSTRING(_in,  3, 2)), ':',
		HEX(SUBSTRING(_in,  5, 2)), ':',
		HEX(SUBSTRING(_in,  7, 2)), ':',
		HEX(SUBSTRING(_in,  9, 2)), ':',
		HEX(SUBSTRING(_in, 11, 2)), ':',
		HEX(SUBSTRING(_in, 13, 2)), ':',
		HEX(SUBSTRING(_in, 15, 2))
	));
END$$

CREATE FUNCTION `INSERT_HTTPSNIFF` (`_oob_time_sec` INT(8) UNSIGNED, `_oob_uid` INT(10) UNSIGNED, `_ip_saddr_BIN` BINARY(16), `_ip_daddr_BIN` BINARY(16), `_tcp_sport` INT(5) UNSIGNED, `_tcp_dport` INT(5) UNSIGNED, `_tcp_ackseq` INT(10) UNSIGNED, `_ip_protocol` TINYINT(3) UNSIGNED, `_httpsniff_host` VARCHAR(255), `_httpsniff_uri` VARCHAR(255), `_httpsniff_method` TINYINT(3) UNSIGNED) RETURNS BIGINT(20) UNSIGNED READS SQL DATA
    SQL SECURITY INVOKER
BEGIN

IF NOT EXISTS(SELECT 1 FROM httpsniff_host_whitelist WHERE httpsniff_host = _httpsniff_host) AND NOT EXISTS(SELECT 1 FROM httpsniff_uid_whitelist WHERE oob_uid = _oob_uid) THEN
	IF ( (_httpsniff_host IS NULL OR _httpsniff_uri IS NULL) AND (SELECT 1 FROM httpsniff WHERE oob_uid = _oob_uid AND tcp_sport = _tcp_sport AND tcp_dport = _tcp_dport AND tcp_ackseq = _tcp_ackseq LIMIT 1) ) THEN
       		BEGIN
		UPDATE httpsniff SET httpsniff_host = IFNULL(httpsniff_host, _httpsniff_host), httpsniff_uri = IFNULL(httpsniff_uri, _httpsniff_uri) WHERE oob_uid = _oob_uid AND tcp_sport = _tcp_sport AND tcp_dport = _tcp_dport AND tcp_ackseq = _tcp_ackseq;
	       END;
	ELSE
       		BEGIN
		INSERT INTO httpsniff (oob_time_sec, oob_uid, ip_saddr_bin, ip_daddr_bin, tcp_sport, tcp_dport, tcp_ackseq, ip_protocol, httpsniff_host, httpsniff_uri, httpsniff_method) VALUES (FROM_UNIXTIME(_oob_time_sec), _oob_uid, _ip_saddr_bin, _ip_daddr_bin, _tcp_sport, _tcp_dport, _tcp_ackseq, _ip_protocol, _httpsniff_host, _httpsniff_uri, IFNULL(_httpsniff_method, 0));
        	END;
	END IF;
END IF;

RETURN LAST_INSERT_ID();
END$$
DELIMITER ;

--
-- Tables
--
CREATE TABLE `httpsniff` (
  `_id` bigint(20) UNSIGNED NOT NULL,
  `oob_time_sec` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `oob_uid` int(10) UNSIGNED DEFAULT NULL,
  `ip_saddr_bin` binary(16) DEFAULT NULL,
  `ip_daddr_bin` binary(16) DEFAULT NULL,
  `tcp_sport` int(5) UNSIGNED DEFAULT NULL,
  `tcp_dport` int(5) UNSIGNED DEFAULT NULL,
  `tcp_ackseq` int(10) UNSIGNED DEFAULT NULL,
  `ip_protocol` tinyint(3) UNSIGNED DEFAULT NULL,
  `httpsniff_host` varchar(255) DEFAULT NULL,
  `httpsniff_uri` varchar(255) DEFAULT NULL,
  `httpsniff_method` enum('GET','POST') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Table for HTTPSNIFF';

CREATE TABLE `httpsniff_host_whitelist` (
  `httpsniff_host` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `httpsniff_host_whitelist` (`httpsniff_host`) VALUES
('api.wordpress.org'),
('appscdn.joomla.org'),
('download.finance.yahoo.com'),
('feeds.feedburner.com'),
('freegeoip.net'),
('graph.facebook.com'),
('images.search.yahoo.com'),
('instagram.com'),
('lh3.ggpht.com'),
('lh4.ggpht.com'),
('lh5.ggpht.com'),
('lh6.ggpht.com'),
('plugins.spip.net'),
('search.yahoo.com'),
('toolbarqueries.google.com'),
('ujquery.org'),
('updates.wpbakery.com'),
('www.facebook.com'),
('www.google-analytics.com'),
('www.google.com'),
('www.imdb.com'),
('www.linkedin.com');

CREATE TABLE `httpsniff_uid_whitelist` (
  `oob_uid` int(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `httpsniff_uid_whitelist` (`oob_uid`) VALUES (0);

-- --------------------------------------------------------

CREATE TABLE `ulog` (
`_id` bigint(20) unsigned
,`oob_time_sec` timestamp
,`oob_uid` int(10) unsigned
,`ip_saddr_bin` varchar(64)
,`ip_daddr_bin` varchar(64)
,`tcp_sport` int(5) unsigned
,`tcp_dport` int(5) unsigned
,`tcp_ackseq` int(10) unsigned
,`ip_protocol` tinyint(3) unsigned
,`httpsniff_host` varchar(255)
,`httpsniff_uri` varchar(255)
,`httpsniff_method` enum('GET','POST')
);

-- --------------------------------------------------------

DROP TABLE IF EXISTS `ulog`;

CREATE ALGORITHM=UNDEFINED SQL SECURITY INVOKER VIEW `ulog`  AS  select `httpsniff`.`_id` AS `_id`,`httpsniff`.`oob_time_sec` AS `oob_time_sec`,`httpsniff`.`oob_uid` AS `oob_uid`,`BIN_TO_IP`(`httpsniff`.`ip_saddr_bin`) AS `ip_saddr_bin`,`BIN_TO_IP`(`httpsniff`.`ip_daddr_bin`) AS `ip_daddr_bin`,`httpsniff`.`tcp_sport` AS `tcp_sport`,`httpsniff`.`tcp_dport` AS `tcp_dport`,`httpsniff`.`tcp_ackseq` AS `tcp_ackseq`,`httpsniff`.`ip_protocol` AS `ip_protocol`,`httpsniff`.`httpsniff_host` AS `httpsniff_host`,`httpsniff`.`httpsniff_uri` AS `httpsniff_uri`,`httpsniff`.`httpsniff_method` AS `httpsniff_method` from `httpsniff` ;

ALTER TABLE `httpsniff`
  ADD PRIMARY KEY (`_id`),
  ADD KEY `tcp_ackseq` (`tcp_ackseq`);

ALTER TABLE `httpsniff_host_whitelist`
  ADD PRIMARY KEY (`httpsniff_host`);

ALTER TABLE `httpsniff_uid_whitelist`
  ADD PRIMARY KEY (`oob_uid`);

ALTER TABLE `httpsniff`
  MODIFY `_id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11593963;

DELIMITER $$
--
-- Events
--
CREATE EVENT `cleanUlogd` ON SCHEDULE EVERY 1 DAY STARTS '2017-10-26 16:12:00' ON COMPLETION NOT PRESERVE ENABLE DO DELETE FROM `ulog` WHERE `oob_time_sec` < NOW() - INTERVAL 60 DAY$$

DELIMITER ;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
