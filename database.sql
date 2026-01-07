-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Počítač: localhost
-- Vytvořeno: Ned 04. led 2026, 05:54
-- Verze serveru: 11.8.3-MariaDB-0+deb13u1 from Debian-log
-- Verze PHP: 8.4.16

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Databáze: `rspamd_quarantine`
--

-- --------------------------------------------------------

--
-- Struktura tabulky `audit_log`
--

CREATE TABLE `audit_log` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `entity_type` varchar(50) DEFAULT 'quarantine',
  `entity_id` int(11) DEFAULT NULL,
  `target_type` varchar(50) DEFAULT NULL,
  `target_id` int(11) DEFAULT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggery `audit_log`
--
DELIMITER $$
CREATE TRIGGER `tr_update_last_login` AFTER INSERT ON `audit_log` FOR EACH ROW BEGIN
    IF NEW.action = 'login_success' THEN
        UPDATE users 
        SET last_login = NEW.timestamp 
        WHERE id = NEW.user_id;
    END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Struktura tabulky `message_trace`
--

CREATE TABLE `message_trace` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `queue_id` varchar(100) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `sender` varchar(255) DEFAULT NULL,
  `recipients` text DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `authenticated_user` varchar(255) DEFAULT NULL,
  `action` varchar(50) DEFAULT NULL,
  `score` decimal(10,2) DEFAULT NULL,
  `symbols` text DEFAULT NULL,
  `size_bytes` int(10) UNSIGNED DEFAULT NULL,
  `headers_from` varchar(255) DEFAULT NULL,
  `headers_to` text DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `metadata_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`metadata_json`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `quarantine_messages`
--

CREATE TABLE `quarantine_messages` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `queue_id` varchar(100) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `sender` varchar(255) DEFAULT NULL,
  `recipients` text DEFAULT NULL,
  `subject` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `authenticated_user` varchar(255) DEFAULT NULL,
  `action` varchar(50) DEFAULT NULL,
  `score` decimal(10,2) DEFAULT NULL,
  `symbols` text DEFAULT NULL,
  `headers_from` varchar(255) DEFAULT NULL,
  `headers_to` text DEFAULT NULL,
  `headers_date` varchar(255) DEFAULT NULL,
  `message_content` longblob DEFAULT NULL,
  `metadata` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`metadata`)),
  `state` tinyint(1) DEFAULT 0,
  `state_at` datetime DEFAULT NULL,
  `state_by` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `sessions`
--

CREATE TABLE `sessions` (
  `id` varchar(128) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `trace_log`
--

CREATE TABLE `trace_log` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `quarantine_id` bigint(20) UNSIGNED DEFAULT NULL,
  `action` varchar(50) DEFAULT NULL,
  `user` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `details` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `trace_statistics`
--

CREATE TABLE `trace_statistics` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `date_hour` datetime DEFAULT NULL,
  `sender_domain` varchar(255) DEFAULT NULL,
  `action` varchar(50) DEFAULT NULL,
  `message_count` int(10) UNSIGNED DEFAULT 0,
  `total_score` decimal(15,2) DEFAULT 0.00,
  `avg_score` decimal(10,2) DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `role` enum('admin','domain_admin','viewer') DEFAULT 'viewer',
  `active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `user_domains`
--

CREATE TABLE `user_domains` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Struktura tabulky `rspamd_map_entries`
--

CREATE TABLE `rspamd_map_entries` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `list_type` enum('whitelist','blacklist') NOT NULL,
  `entry_type` enum('ip','email') NOT NULL,
  `entry_value` varchar(255) NOT NULL,
  `created_by` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_daily_stats`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_daily_stats` (
`date` date
,`action` varchar(50)
,`count` bigint(21)
,`avg_score` decimal(14,6)
,`max_score` decimal(10,2)
,`unique_senders` bigint(21)
,`unique_ips` bigint(21)
);

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_quarantine_stats_by_domain`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_quarantine_stats_by_domain` (
);

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_spam_ips`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_spam_ips` (
`ip_address` varchar(45)
,`total_messages` bigint(21)
,`rejected` decimal(22,0)
,`avg_score` decimal(14,6)
,`sender_count` bigint(21)
,`last_seen` datetime
);

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_top_spammers`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_top_spammers` (
`sender` varchar(255)
,`spam_count` bigint(21)
,`avg_score` decimal(14,6)
,`max_score` decimal(10,2)
,`ip_count` bigint(21)
,`last_seen` datetime
);

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_users_with_domains`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_users_with_domains` (
`id` int(11)
,`username` varchar(100)
,`email` varchar(255)
,`role` enum('admin','domain_admin','viewer')
,`active` tinyint(1)
,`created_at` timestamp
,`last_login` timestamp
,`domains` mediumtext
);

-- --------------------------------------------------------

--
-- Zástupná struktura pro pohled `v_user_activity`
-- (Vlastní pohled viz níže)
--
CREATE TABLE `v_user_activity` (
`username` varchar(100)
,`trace_actions` bigint(21)
,`last_trace_action` datetime
,`audit_actions` bigint(21)
,`last_audit_action` timestamp
);

--
-- Indexy pro exportované tabulky
--

--
-- Indexy pro tabulku `audit_log`
--
ALTER TABLE `audit_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_username` (`username`),
  ADD KEY `idx_timestamp` (`timestamp`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexy pro tabulku `message_trace`
--
ALTER TABLE `message_trace`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_timestamp` (`timestamp`),
  ADD KEY `idx_sender` (`sender`),
  ADD KEY `idx_recipients` (`recipients`(255)),
  ADD KEY `idx_message_id` (`message_id`),
  ADD KEY `idx_queue_id` (`queue_id`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_ip` (`ip_address`),
  ADD KEY `idx_user` (`authenticated_user`),
  ADD KEY `idx_score` (`score`),
  ADD KEY `idx_composite` (`timestamp`,`action`,`score`);

--
-- Indexy pro tabulku `quarantine_messages`
--
ALTER TABLE `quarantine_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_timestamp` (`timestamp`),
  ADD KEY `idx_sender` (`sender`),
  ADD KEY `idx_message_id` (`message_id`),
  ADD KEY `idx_queue_id` (`queue_id`),
  ADD KEY `idx_action` (`action`),
  ADD KEY `idx_released` (`state`);

--
-- Indexy pro tabulku `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_expires_at` (`expires_at`);

--
-- Indexy pro tabulku `trace_log`
--
ALTER TABLE `trace_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `quarantine_id` (`quarantine_id`),
  ADD KEY `idx_timestamp` (`timestamp`),
  ADD KEY `idx_action` (`action`);

--
-- Indexy pro tabulku `trace_statistics`
--
ALTER TABLE `trace_statistics`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_stat` (`date_hour`,`sender_domain`,`action`),
  ADD KEY `idx_date` (`date_hour`),
  ADD KEY `idx_domain` (`sender_domain`);

--
-- Indexy pro tabulku `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `idx_username` (`username`),
  ADD KEY `idx_role` (`role`),
  ADD KEY `idx_active` (`active`);

--
-- Indexy pro tabulku `user_domains`
--
ALTER TABLE `user_domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_domain` (`user_id`,`domain`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_domain` (`domain`);

--
-- Indexy pro tabulku `rspamd_map_entries`
--
ALTER TABLE `rspamd_map_entries`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_map_entry` (`list_type`,`entry_type`,`entry_value`),
  ADD KEY `idx_list_type` (`list_type`),
  ADD KEY `idx_entry_type` (`entry_type`),
  ADD KEY `idx_entry_value` (`entry_value`);

--
-- AUTO_INCREMENT pro tabulky
--

--
-- AUTO_INCREMENT pro tabulku `audit_log`
--
ALTER TABLE `audit_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `message_trace`
--
ALTER TABLE `message_trace`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `quarantine_messages`
--
ALTER TABLE `quarantine_messages`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `trace_log`
--
ALTER TABLE `trace_log`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `trace_statistics`
--
ALTER TABLE `trace_statistics`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `user_domains`
--
ALTER TABLE `user_domains`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pro tabulku `rspamd_map_entries`
--
ALTER TABLE `rspamd_map_entries`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_daily_stats`
--
DROP TABLE IF EXISTS `v_daily_stats`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_daily_stats`  AS SELECT cast(`message_trace`.`timestamp` as date) AS `date`, `message_trace`.`action` AS `action`, count(0) AS `count`, avg(`message_trace`.`score`) AS `avg_score`, max(`message_trace`.`score`) AS `max_score`, count(distinct `message_trace`.`sender`) AS `unique_senders`, count(distinct `message_trace`.`ip_address`) AS `unique_ips` FROM `message_trace` WHERE `message_trace`.`timestamp` >= current_timestamp() - interval 30 day GROUP BY cast(`message_trace`.`timestamp` as date), `message_trace`.`action` ORDER BY cast(`message_trace`.`timestamp` as date) DESC, count(0) DESC ;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_quarantine_stats_by_domain`
--
DROP TABLE IF EXISTS `v_quarantine_stats_by_domain`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_quarantine_stats_by_domain`  AS SELECT substring_index(`quarantine_messages`.`recipients`,'@',-1) AS `domain`, count(0) AS `total_messages`, sum(case when `quarantine_messages`.`released` = 0 then 1 else 0 end) AS `in_quarantine`, sum(case when `quarantine_messages`.`released` = 1 then 1 else 0 end) AS `released`, avg(`quarantine_messages`.`score`) AS `avg_score`, max(`quarantine_messages`.`timestamp`) AS `last_message` FROM `quarantine_messages` GROUP BY substring_index(`quarantine_messages`.`recipients`,'@',-1) ;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_spam_ips`
--
DROP TABLE IF EXISTS `v_spam_ips`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_ips`  AS SELECT `message_trace`.`ip_address` AS `ip_address`, count(0) AS `total_messages`, sum(case when `message_trace`.`action` = 'reject' then 1 else 0 end) AS `rejected`, avg(`message_trace`.`score`) AS `avg_score`, count(distinct `message_trace`.`sender`) AS `sender_count`, max(`message_trace`.`timestamp`) AS `last_seen` FROM `message_trace` WHERE `message_trace`.`timestamp` >= current_timestamp() - interval 7 day GROUP BY `message_trace`.`ip_address` HAVING `avg_score` > 5 ORDER BY sum(case when `message_trace`.`action` = 'reject' then 1 else 0 end) DESC, avg(`message_trace`.`score`) DESC LIMIT 0, 100 ;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_top_spammers`
--
DROP TABLE IF EXISTS `v_top_spammers`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_top_spammers`  AS SELECT `message_trace`.`sender` AS `sender`, count(0) AS `spam_count`, avg(`message_trace`.`score`) AS `avg_score`, max(`message_trace`.`score`) AS `max_score`, count(distinct `message_trace`.`ip_address`) AS `ip_count`, max(`message_trace`.`timestamp`) AS `last_seen` FROM `message_trace` WHERE `message_trace`.`score` > 5 AND `message_trace`.`timestamp` >= current_timestamp() - interval 7 day GROUP BY `message_trace`.`sender` HAVING `spam_count` > 5 ORDER BY count(0) DESC, avg(`message_trace`.`score`) DESC LIMIT 0, 100 ;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_users_with_domains`
--
DROP TABLE IF EXISTS `v_users_with_domains`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_users_with_domains`  AS SELECT `u`.`id` AS `id`, `u`.`username` AS `username`, `u`.`email` AS `email`, `u`.`role` AS `role`, `u`.`active` AS `active`, `u`.`created_at` AS `created_at`, `u`.`last_login` AS `last_login`, group_concat(`ud`.`domain` order by `ud`.`domain` ASC separator ', ') AS `domains` FROM (`users` `u` left join `user_domains` `ud` on(`u`.`id` = `ud`.`user_id`)) GROUP BY `u`.`id`, `u`.`username`, `u`.`email`, `u`.`role`, `u`.`active`, `u`.`created_at`, `u`.`last_login` ;

-- --------------------------------------------------------

--
-- Struktura pro pohled `v_user_activity`
--
DROP TABLE IF EXISTS `v_user_activity`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_user_activity`  AS SELECT `u`.`username` AS `username`, count(distinct `tl`.`id`) AS `trace_actions`, max(`tl`.`timestamp`) AS `last_trace_action`, count(distinct `al`.`id`) AS `audit_actions`, max(`al`.`timestamp`) AS `last_audit_action` FROM ((`users` `u` left join `trace_log` `tl` on(`u`.`username` = `tl`.`user`)) left join `audit_log` `al` on(`u`.`id` = `al`.`user_id`)) GROUP BY `u`.`id`, `u`.`username` ;

--
-- Omezení pro exportované tabulky
--

--
-- Omezení pro tabulku `audit_log`
--
ALTER TABLE `audit_log`
  ADD CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Omezení pro tabulku `sessions`
--
ALTER TABLE `sessions`
  ADD CONSTRAINT `sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Omezení pro tabulku `trace_log`
--
ALTER TABLE `trace_log`
  ADD CONSTRAINT `trace_log_ibfk_1` FOREIGN KEY (`quarantine_id`) REFERENCES `quarantine_messages` (`id`) ON DELETE CASCADE;

--
-- Omezení pro tabulku `user_domains`
--
ALTER TABLE `user_domains`
  ADD CONSTRAINT `user_domains_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
