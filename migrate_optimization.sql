-- =============================================================================
-- Migrační skript: DB optimalizace (Fáze 1 + 2 + 3)
-- Cílová verze: MariaDB 11.x
-- Spuštění: mysql -u root -p rspamd_quarantine < migrate_optimization.sql
--
-- PŘED SPUŠTĚNÍM:
--   1. Zazálohuj databázi: mysqldump rspamd_quarantine > backup_before_migration.sql
--   2. Skript je idempotentní tam, kde to MariaDB umožňuje.
--      Tam kde ne, selhání kroku je označeno komentářem – ověř stav ručně.
--   3. Kroky s ALTERem particionované tabulky způsobují implicitní COMMIT.
--      Celý skript proto nelze obalit do jedné transakce.
-- =============================================================================

SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO';
SET foreign_key_checks = 0;

SELECT '=== START MIGRACE ===' AS info;

-- =============================================================================
-- FÁZE 1 – View, composite indexy
-- =============================================================================

SELECT '--- Fáze 1: View a composite indexy ---' AS info;

-- -----------------------------------------------------------------------------
-- 1.1  Oprava view v_quarantine_stats_by_domain
--      Sloupec `released` neexistuje – správný je `state`.
-- -----------------------------------------------------------------------------
SELECT '1.1 Oprava view v_quarantine_stats_by_domain' AS info;

CREATE OR REPLACE ALGORITHM=UNDEFINED
  DEFINER=`root`@`localhost`
  SQL SECURITY DEFINER
VIEW `v_quarantine_stats_by_domain` AS
SELECT
  SUBSTRING_INDEX(`quarantine_messages`.`recipients`, '@', -1) AS `domain`,
  COUNT(0)                                                      AS `total_messages`,
  SUM(CASE WHEN `quarantine_messages`.`state` = 0 THEN 1 ELSE 0 END) AS `in_quarantine`,
  SUM(CASE WHEN `quarantine_messages`.`state` = 1 THEN 1 ELSE 0 END) AS `released`,
  AVG(`quarantine_messages`.`score`)                            AS `avg_score`,
  MAX(`quarantine_messages`.`timestamp`)                        AS `last_message`
FROM `quarantine_messages`
GROUP BY SUBSTRING_INDEX(`quarantine_messages`.`recipients`, '@', -1);

SELECT '  OK: view opraven' AS info;

-- -----------------------------------------------------------------------------
-- 1.2  quarantine_messages – přechod na composite indexy
--      Odstraníme slabé jednosloupcové, přidáme composite.
-- -----------------------------------------------------------------------------
SELECT '1.2 quarantine_messages – composite indexy' AS info;

-- smaž staré jednosloupcové indexy (IF EXISTS dostupné od MariaDB 10.1.4)
ALTER TABLE `quarantine_messages`
  DROP INDEX IF EXISTS `idx_timestamp`,
  DROP INDEX IF EXISTS `idx_sender`,
  DROP INDEX IF EXISTS `idx_action`,
  DROP INDEX IF EXISTS `idx_released`;

-- přidej composite indexy (IF NOT EXISTS dostupné od MariaDB 10.1.4)
ALTER TABLE `quarantine_messages`
  ADD INDEX IF NOT EXISTS `idx_state_ts`      (`state`, `timestamp`),
  ADD INDEX IF NOT EXISTS `idx_state_state_at` (`state`, `state_at`),
  ADD INDEX IF NOT EXISTS `idx_sender_ts`     (`sender`, `timestamp`),
  ADD INDEX IF NOT EXISTS `idx_user_ts`       (`authenticated_user`, `timestamp`);

SELECT '  OK: quarantine_messages indexy hotovy' AS info;

-- -----------------------------------------------------------------------------
-- 1.3  message_trace – composite indexy
--      Jednosloupcové indexy odstraníme teď; PK změníme v Fázi 3
--      (musí být součástí jednoho ALTER před partitioningem).
-- -----------------------------------------------------------------------------
SELECT '1.3 message_trace – composite indexy' AS info;

ALTER TABLE `message_trace`
  DROP INDEX IF EXISTS `idx_timestamp`,
  DROP INDEX IF EXISTS `idx_sender`,
  DROP INDEX IF EXISTS `idx_action`,
  DROP INDEX IF EXISTS `idx_ip`,
  DROP INDEX IF EXISTS `idx_score`,
  DROP INDEX IF EXISTS `idx_composite`,
  DROP INDEX IF EXISTS `idx_recipients`;

ALTER TABLE `message_trace`
  ADD INDEX IF NOT EXISTS `idx_ts_action`       (`timestamp`, `action`),
  ADD INDEX IF NOT EXISTS `idx_ts_ip_action`    (`timestamp`, `ip_address`, `action`),
  ADD INDEX IF NOT EXISTS `idx_ts_sender_score` (`timestamp`, `sender`, `score`);

SELECT '  OK: message_trace indexy (bez PK a partitioningu) hotovy' AS info;

-- =============================================================================
-- FÁZE 2 – Blob separace + generated columns
-- =============================================================================

SELECT '--- Fáze 2: Blob separace a generated columns ---' AS info;

-- -----------------------------------------------------------------------------
-- 2.1  Vytvoř quarantine_message_blob (1:1 s quarantine_messages)
-- -----------------------------------------------------------------------------
SELECT '2.1 Vytváření tabulky quarantine_message_blob' AS info;

CREATE TABLE IF NOT EXISTS `quarantine_message_blob` (
  `quarantine_id` bigint(20) UNSIGNED NOT NULL,
  `message_content` longblob NOT NULL,
  PRIMARY KEY (`quarantine_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SELECT '  OK: tabulka existuje (nebo byla vytvořena)' AS info;

-- -----------------------------------------------------------------------------
-- 2.2  Migrace dat: přesun message_content do blob tabulky
--      INSERT IGNORE přeskočí řádky které tam už jsou (re-run safe).
-- -----------------------------------------------------------------------------
SELECT '2.2 Migrace message_content dat' AS info;

INSERT IGNORE INTO `quarantine_message_blob` (`quarantine_id`, `message_content`)
SELECT `id`, `message_content`
FROM `quarantine_messages`
WHERE `message_content` IS NOT NULL;

SELECT CONCAT('  OK: migrováno řádků = ', ROW_COUNT()) AS info;

-- -----------------------------------------------------------------------------
-- 2.3  Přidej FK na quarantine_message_blob (pokud ještě neexistuje)
-- -----------------------------------------------------------------------------
SELECT '2.3 FK pro quarantine_message_blob' AS info;

-- MariaDB nemá IF NOT EXISTS pro CONSTRAINT – ochrání nás kontrola v information_schema
SET @fk_exists = (
  SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'quarantine_message_blob'
    AND CONSTRAINT_NAME = 'fk_qmb_quarantine_messages'
);

SET @sql = IF(@fk_exists = 0,
  'ALTER TABLE `quarantine_message_blob`
     ADD CONSTRAINT `fk_qmb_quarantine_messages`
       FOREIGN KEY (`quarantine_id`) REFERENCES `quarantine_messages` (`id`) ON DELETE CASCADE',
  'SELECT "  SKIP: FK již existuje" AS info'
);

PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 2.4  Ověř integritu před smazáním sloupce
--      Pokud se počty neshodují, skript selže a NEDROPNE sloupec.
-- -----------------------------------------------------------------------------
SELECT '2.4 Ověření integrity migrace' AS info;

SELECT
  CASE
    WHEN
      (SELECT COUNT(*) FROM `quarantine_messages` WHERE `message_content` IS NOT NULL) =
      (SELECT COUNT(*) FROM `quarantine_message_blob`)
    THEN '  OK: počty se shodují, migrace je kompletní'
    ELSE '  CHYBA: počty se neshodují! Zkontroluj data před pokračováním.'
  END AS integrity_check;

-- Zastav skript pokud počty nesedí
-- (Signal způsobí rollback případné otevřené transakce a skript se přeruší)
SET @src_count = (SELECT COUNT(*) FROM `quarantine_messages` WHERE `message_content` IS NOT NULL);
SET @dst_count = (SELECT COUNT(*) FROM `quarantine_message_blob`);

SET @integrity_ok = IF(@src_count = @dst_count, 1, 0);

SET @integrity_sql = IF(@integrity_ok = 1,
  'SELECT "  Integrita OK, pokračuji s DROP COLUMN" AS info',
  'SIGNAL SQLSTATE "45000" SET MESSAGE_TEXT = "MIGRACE PŘERUŠENA: quarantine_message_blob neobsahuje všechna data z quarantine_messages. Spusť 2.2 znovu."'
);
PREPARE stmt FROM @integrity_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 2.5  Odstraň message_content z quarantine_messages
-- -----------------------------------------------------------------------------
SELECT '2.5 DROP COLUMN message_content' AS info;

SET @col_exists = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'quarantine_messages'
    AND COLUMN_NAME = 'message_content'
);

SET @sql = IF(@col_exists > 0,
  'ALTER TABLE `quarantine_messages` DROP COLUMN `message_content`',
  'SELECT "  SKIP: sloupec již byl odstraněn" AS info'
);

PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 2.6  Změna typu subject z TEXT na VARCHAR(500) v quarantine_messages
-- -----------------------------------------------------------------------------
SELECT '2.6 Změna subject TEXT -> VARCHAR(500)' AS info;

SET @col_type = (
  SELECT DATA_TYPE FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'quarantine_messages'
    AND COLUMN_NAME = 'subject'
);

SET @sql = IF(@col_type = 'text',
  'ALTER TABLE `quarantine_messages` MODIFY COLUMN `subject` varchar(500) DEFAULT NULL',
  'SELECT "  SKIP: subject je již VARCHAR nebo byl upraven jinak" AS info'
);

PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 2.7  Generated columns v message_trace
--      PERSISTENT = uložené na disku, indexovatelné
-- -----------------------------------------------------------------------------
SELECT '2.7 Generated columns: sender_domain, sender_lc' AS info;

SET @col_exists = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'message_trace'
    AND COLUMN_NAME = 'sender_domain'
);

SET @sql = IF(@col_exists = 0,
  'ALTER TABLE `message_trace`
     ADD COLUMN `sender_domain` varchar(255) GENERATED ALWAYS AS (SUBSTRING_INDEX(`sender`, "@", -1)) PERSISTENT,
     ADD COLUMN `sender_lc`     varchar(255) GENERATED ALWAYS AS (LOWER(`sender`)) PERSISTENT',
  'SELECT "  SKIP: generated columns již existují" AS info'
);

PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Index na generated column přidáme až po vytvoření sloupce
ALTER TABLE `message_trace`
  ADD INDEX IF NOT EXISTS `idx_sender_domain_ts` (`sender_domain`, `timestamp`);

SELECT '  OK: generated columns a index hotovy' AS info;

-- =============================================================================
-- FÁZE 3 – PRIMARY KEY + RANGE partitioning message_trace
-- =============================================================================
-- POZOR: ALTER TABLE s PARTITION BY způsobuje implicitní COMMIT.
--        Celý krok je DML-safe (data se nepřepisují, jen reorganizují),
--        ale je NEVRATNÝ bez backupu.
-- =============================================================================

SELECT '--- Fáze 3: PK změna a partitioning message_trace ---' AS info;

-- -----------------------------------------------------------------------------
-- 3.1  Ověř, zda tabulka ještě není particionovaná
-- -----------------------------------------------------------------------------
SELECT '3.1 Kontrola stavu partitioningu' AS info;

SET @already_partitioned = (
  SELECT COUNT(*) FROM information_schema.PARTITIONS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'message_trace'
    AND PARTITION_METHOD IS NOT NULL
);

SELECT IF(@already_partitioned > 0,
  '  INFO: tabulka je již particionována – kroky 3.2 a 3.3 budou přeskočeny',
  '  INFO: tabulka není particionována – pokračuji'
) AS info;

-- -----------------------------------------------------------------------------
-- 3.2  Změna PRIMARY KEY na (id, timestamp)
--      Musí proběhnout před PARTITION BY – partition key musí být v PK.
-- -----------------------------------------------------------------------------
SET @sql = IF(@already_partitioned = 0,
  'ALTER TABLE `message_trace`
     DROP PRIMARY KEY,
     ADD PRIMARY KEY (`id`, `timestamp`)',
  'SELECT "  SKIP: PK změna – tabulka je již particionována" AS info'
);

SELECT '3.2 Změna PRIMARY KEY na (id, timestamp)' AS info;
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 3.3  PARTITION BY RANGE COLUMNS(timestamp)
--      Měsíční oddíly od 2025-01 do 2026-12 + catch-all pmax.
--      Přidání nového měsíce: ALTER TABLE message_trace REORGANIZE PARTITION pmax INTO (...)
--      Smazání starých dat:   ALTER TABLE message_trace DROP PARTITION p2025_01;
-- -----------------------------------------------------------------------------
SELECT '3.3 Aplikace RANGE partitioningu' AS info;

SET @sql = IF(@already_partitioned = 0,
  'ALTER TABLE `message_trace`
     PARTITION BY RANGE COLUMNS(`timestamp`) (
       PARTITION `p2025_01` VALUES LESS THAN (''2025-02-01''),
       PARTITION `p2025_02` VALUES LESS THAN (''2025-03-01''),
       PARTITION `p2025_03` VALUES LESS THAN (''2025-04-01''),
       PARTITION `p2025_04` VALUES LESS THAN (''2025-05-01''),
       PARTITION `p2025_05` VALUES LESS THAN (''2025-06-01''),
       PARTITION `p2025_06` VALUES LESS THAN (''2025-07-01''),
       PARTITION `p2025_07` VALUES LESS THAN (''2025-08-01''),
       PARTITION `p2025_08` VALUES LESS THAN (''2025-09-01''),
       PARTITION `p2025_09` VALUES LESS THAN (''2025-10-01''),
       PARTITION `p2025_10` VALUES LESS THAN (''2025-11-01''),
       PARTITION `p2025_11` VALUES LESS THAN (''2025-12-01''),
       PARTITION `p2025_12` VALUES LESS THAN (''2026-01-01''),
       PARTITION `p2026_01` VALUES LESS THAN (''2026-02-01''),
       PARTITION `p2026_02` VALUES LESS THAN (''2026-03-01''),
       PARTITION `p2026_03` VALUES LESS THAN (''2026-04-01''),
       PARTITION `p2026_04` VALUES LESS THAN (''2026-05-01''),
       PARTITION `p2026_05` VALUES LESS THAN (''2026-06-01''),
       PARTITION `p2026_06` VALUES LESS THAN (''2026-07-01''),
       PARTITION `p2026_07` VALUES LESS THAN (''2026-08-01''),
       PARTITION `p2026_08` VALUES LESS THAN (''2026-09-01''),
       PARTITION `p2026_09` VALUES LESS THAN (''2026-10-01''),
       PARTITION `p2026_10` VALUES LESS THAN (''2026-11-01''),
       PARTITION `p2026_11` VALUES LESS THAN (''2026-12-01''),
       PARTITION `p2026_12` VALUES LESS THAN (''2027-01-01''),
       PARTITION `pmax`     VALUES LESS THAN (MAXVALUE)
     )',
  'SELECT "  SKIP: partitioning – tabulka je již particionována" AS info'
);

PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT '  OK: partitioning aplikován' AS info;

-- =============================================================================
-- SOUHRN
-- =============================================================================

SELECT '=== MIGRACE DOKONČENA ===' AS info;

SELECT 'Ověření výsledného stavu:' AS info;

SELECT
  TABLE_NAME,
  TABLE_ROWS,
  ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN ('message_trace', 'quarantine_messages', 'quarantine_message_blob')
ORDER BY TABLE_NAME;

SELECT 'Počet partitions v message_trace:' AS info;
SELECT COUNT(*) AS partition_count
FROM information_schema.PARTITIONS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'message_trace'
  AND PARTITION_NAME IS NOT NULL;

SELECT 'Indexy message_trace:' AS info;
SELECT INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'message_trace'
GROUP BY INDEX_NAME
ORDER BY INDEX_NAME;

SELECT 'Indexy quarantine_messages:' AS info;
SELECT INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'quarantine_messages'
GROUP BY INDEX_NAME
ORDER BY INDEX_NAME;

SET foreign_key_checks = 1;
