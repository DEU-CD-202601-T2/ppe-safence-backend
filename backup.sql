/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.11.14-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: capstone_db
-- ------------------------------------------------------
-- Server version	10.11.14-MariaDB-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `alarms`
--

DROP TABLE IF EXISTS `alarms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `alarms` (
  `id` varchar(100) NOT NULL,
  `type` varchar(100) DEFAULT NULL,
  `time` datetime DEFAULT NULL,
  `area_id` int(11) DEFAULT NULL,
  `status` varchar(20) DEFAULT '미해결',
  `image_url` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_area_id` (`area_id`),
  CONSTRAINT `fk_alarms_area` FOREIGN KEY (`area_id`) REFERENCES `areas` (`area_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alarms`
--

LOCK TABLES `alarms` WRITE;
/*!40000 ALTER TABLE `alarms` DISABLE KEYS */;
INSERT INTO `alarms` VALUES
('20260507100000','마스크 미착용','2026-05-07 10:00:00',1,'미해결','http://43.200.27.117:5000/images/sample_a.jpg'),
('20260507100100','헬멧 미착용','2026-05-07 10:01:00',2,'미해결','http://43.200.27.117:5000/images/sample_b.jpg');
/*!40000 ALTER TABLE `alarms` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `areas`
--

DROP TABLE IF EXISTS `areas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `areas` (
  `area_id` int(11) NOT NULL AUTO_INCREMENT,
  `area_name` varchar(50) NOT NULL COMMENT '사용자에게 보일 구역 이름 (예: A구역)',
  `area_code` varchar(20) DEFAULT NULL COMMENT 'User.zone과 매칭되는 코드 (예: ZONE_A)',
  `camera_key` varchar(100) DEFAULT NULL COMMENT '보드에서 받은 영구 카메라 식별자. NULL=카메라 미배치',
  `description` varchar(255) DEFAULT NULL COMMENT '운영 메모 (포트 위치, 라벨, 주의사항 등)',
  `risk_level` varchar(20) DEFAULT 'normal' COMMENT 'low | normal | high',
  `is_active` tinyint(1) DEFAULT 1 COMMENT '비활성 시 화면/알림에서 제외 (soft delete)',
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`area_id`),
  UNIQUE KEY `area_name` (`area_name`),
  UNIQUE KEY `area_code` (`area_code`),
  UNIQUE KEY `camera_key` (`camera_key`),
  KEY `idx_active` (`is_active`),
  KEY `idx_risk` (`risk_level`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='구역 및 카메라 매핑';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `areas`
--

LOCK TABLES `areas` WRITE;
/*!40000 ALTER TABLE `areas` DISABLE KEYS */;
INSERT INTO `areas` VALUES
(1,'A구역','ZONE_A','USB_2304_4922_PORT_1-2.1','Jetson USB 포트 1-2.1 (KS2A418-2.0). 시리얼 없음 - 포트 변경 시 camera_key 재등록 필요.','normal',1,'2026-05-06 22:04:39','2026-05-06 22:04:39'),
(2,'B구역','ZONE_B','RS_241122303805','Intel RealSense D435','high',1,'2026-05-06 23:11:35','2026-05-07 04:54:49');
/*!40000 ALTER TABLE `areas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_areas`
--

DROP TABLE IF EXISTS `user_areas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_areas` (
  `user_id` int(11) NOT NULL,
  `area_id` int(11) NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`user_id`,`area_id`),
  KEY `idx_ua_area` (`area_id`),
  CONSTRAINT `fk_ua_area` FOREIGN KEY (`area_id`) REFERENCES `areas` (`area_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ua_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='사용자-구역 N:M 매핑';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_areas`
--

LOCK TABLES `user_areas` WRITE;
/*!40000 ALTER TABLE `user_areas` DISABLE KEYS */;
INSERT INTO `user_areas` VALUES
(90,1,'2026-05-06 23:08:27'),
(90,2,'2026-05-06 23:11:35');
/*!40000 ALTER TABLE `user_areas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `login_id` varchar(50) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `login_id` (`login_id`)
) ENGINE=InnoDB AUTO_INCREMENT=119 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES
(90,'a001','정성훈','scrypt:32768:8:1$OUdA1ns4LNihAnrt$3fd848912476c140f44b1250eb7be59b1f9874e2a5ab1449ffe4ab0236b263899521336e01b9268a84ce6528850c576cf41afc3275997bd6d26311891a76b092','최고 관리자'),
(91,'a002','김도윤','scrypt:32768:8:1$zRhai4BPqxMJBEYW$d93c78b9b8686c39f0eea273c6328f68673c9401e499e1465fa32e01cce39793b22876413b014a09981b78d10009775676bbcc55b341a840109690034b592c1f','구역 매니저'),
(92,'a003','최준호','scrypt:32768:8:1$5sTurwvUEUAbvJIA$e46ffb4d2f51f144f8838b5699566ce4cb89bb43ab6c0c0a0b877bb2c25be348ead79526f8ae1cf3b98e91f39473d4b534d253c98cb65ce049327b300b4a8114','보안 팀장'),
(93,'u001','박태양','scrypt:32768:8:1$CFbRC0aqaNVhwkfW$673597ff30eb1c883642b4268ba62dac2823bc27ad41cf8d79cbca93d6639dcd9085aedbc1bc273c7080e3d7ffefbe2e68d7ba5dc32ccefa92d0beb75393679b','작업자'),
(94,'u002','이현우','scrypt:32768:8:1$oMfDcm8ZMCx9w1cd$07faae67346253e396ec37aa4b5e578d3209ee8b9b40176dbc47ff4b4f6b1f5b5b64deef183dc43809766c9eb6ab8fc735f9ce578eda83ef38a894fb91663995','작업자'),
(95,'u003','한상준','scrypt:32768:8:1$KpASwf2y9R6BWsRN$44179f027fa03e9a0cb0623960388042ae1d34e647f9f909780c10a001acda67bd72fe4b833136c9550af1b2fa4cbf540ef819767ea0be4241f8a17e6d989fc9','작업자'),
(96,'u004','강민재','scrypt:32768:8:1$BlwyhNpX7GONtp8P$b06c3131a78021d9ae6b2b6121077a5749961ba79d0352bdb4ba99ba57420c75df0754bf8c13192864af8e2151913f5b7775de92984f33c3eadc06cbe5791919','작업자'),
(97,'u005','윤성민','scrypt:32768:8:1$DFTp1humAq3h9kV7$a8914e95c5152f4382db97ab9d6a54b4627d8eddcc3241147651e20aa2a4aa26bca250f8b9b5acda815bc79f73b737e9eee16862b50c7cb3cfecc1b56daebb8c','작업자'),
(98,'u006','조현수','scrypt:32768:8:1$qEnnZz7EbGedACnS$799ed3bef7c5ea33e5d0cb9fc3cc920d76a3c1a60f25f922d08b69df412591723c41844c6386224d9b21f07032a54b72d41ed371421f2e49ddb7348f5f7c1bb7','작업자'),
(99,'u007','백건우','scrypt:32768:8:1$pLBmg8aO3ktxWzWm$5219451f5956656d19847dc403d26b3fe65a04d1a864429091d64c1cc476241e9c4633ecf589caa3bffbe6dfbbf0e1318a07c165ab14492480b7c650d75df025','작업자'),
(100,'u008','임지훈','scrypt:32768:8:1$4BSpRTgQVujEEpXz$5f89e13e70804e8dd931d553a81c0838e3ea3ea733a239915320004809a49736c747ec8e4a43d136bf875f377122cede4902dd8dd0adde4d795a77217506ff1c','작업자'),
(101,'u009','오현석','scrypt:32768:8:1$y38L8eOjTItMJjVv$8f2f7d36a55f47881e76f7ca5cb3f5950ae7d88f179978f338537c3746f2f348fd91f7dfd5c8391a636f317b051045bdb9045a8f33d8002cb3c03f427ea3f2a4','작업자'),
(102,'u010','서민석','scrypt:32768:8:1$SrNmTkf8mZUo5ksu$3e95421bb956badc4a5eb18307a5de675ce8d025f1cd6fe8cbd07814d401f6213c574a711f57a1acd7a47c6f0cb846021800d48bf85b333b5be60f29b4a7f814','작업자'),
(103,'u011','장우진','scrypt:32768:8:1$V7UsE7E85kqA1QKi$06fce4103ee587a74bbc72bc8e466e5b10c374adb6587dccd188a4364ba3f957a56af667e6c80cb4ca41790d88a85e9f7941ddabf58ee68172d5f1a65d57c10f','작업자'),
(104,'u012','권영수','scrypt:32768:8:1$85yuoHLaQ0GgEX1o$f543076521ffcff67b474ea74dc670454a54f8348525dd8ff3fed86c1623150ef0089d64e21edd7d2ecc6c4088c5e4d7d750c839712f43aafb2248f5e00a0bc1','작업자'),
(105,'u013','배태준','scrypt:32768:8:1$jiGxaIPZOV2zBOmA$a8484b5f3a26ccf7ee9b0ab0a16382de7a7784208ae8cacbbd132d54dee59e6bdfb51c901641fd2fce1d861194640a6265468c9dc9bb40da09f6c3d4a5c33c23','작업자'),
(106,'u014','유진서','scrypt:32768:8:1$1pYQndSoZBJ1C7XC$4bbcb5c18990072b7b863aebad58bf06ea7dd11c5b9349e34c0e850be3271d23cd4cd637e2df4124004b801a915d32ab3e88778cd9ac58839a2e7a5a06db6d5d','작업자'),
(107,'u015','안승현','scrypt:32768:8:1$0E0y1tWewhu8H6UQ$415ebf65762b566c99171f057b24d04d4c31150656e900325d2a1a342a1d4ed063d91e4c8ed7a5e72e873f59decd27e6f48bf377892fb5377e5823c55a1a537d','작업자'),
(108,'u016','하재욱','scrypt:32768:8:1$AQGwiFnCYjTSdPbD$28ffca2aaaec693b56b132b46081df1e2bad39e9846aec55ea58a921b38a397e9175de671b8f6e8e0f465421a5d267cefba3bb2798260ce81ce02de78d74b94e','작업자'),
(109,'u017','손동준','scrypt:32768:8:1$u32elgBcKqWpiikZ$cc2aada2aa40327694e2d254fb94b0e687fb548bc649405f99df7cdbc58ed9aecc59293c898b8c4459f6df8fedb6f1a8f4651d42cbef068a24bf7ec5faaa01a9','작업자'),
(110,'u018','양진우','scrypt:32768:8:1$HlR2lfH1VW1ejD0m$40af7bebe0117037545c44c28136ad30dacbf91a0cd026f961738a7062374d708a84ca0ce02b1003c5b8993f40198a6b3a92e04a118dd8948d72ae3634e41a19','작업자'),
(111,'u019','노승우','scrypt:32768:8:1$rowlTnoUowrIU4TA$22083026a6073576dd6a42716b8842741bed18ac7e6f167213cb25e10c705165e7b655f3d53dae756f6d1529f505a2f8383bdbe2fd5270bdf729b8f77f86bd29','작업자'),
(112,'u020','신지호','scrypt:32768:8:1$WBOGAMjNabKq11Pu$a669c6d21f81f44877bf0dbfd73b79151d3ec98a97503d44d6703c037b8e673fdcb64eb8e0bedf92e162cf3b4f88e36c1a7fa2c96c51668fbf165438f95ea5f9','작업자'),
(113,'u021','문준영','scrypt:32768:8:1$BCtWsnKLlSd19yUv$27d7b4078c3cee47892c00794be86ca636882d8d56219e6f17b8731c2715310a78110359b70e2e3c8961af10ff18cd38d263584cea69e80c623398929016ed51','작업자'),
(114,'u022','홍태수','scrypt:32768:8:1$swkAA5u12vWUwk7F$d8907259cf083712fc59e0b6a953d4b95b6094896784b0f39068bddb64706988371bc84b59c33733b6197ee892e7189a616062da50beb0b30aed77b036687e7f','작업자'),
(115,'u023','고영민','scrypt:32768:8:1$ArEVQ0UqwsOQvaRh$6ec99182f306eb529851284cee0c716a275702bfdf6d15d6ded9446d7d7aebea85b26fb4f092ae337a183b9a8e3e6e23adb160710f44c643bd61a7a1b8c0fab4','작업자'),
(116,'u024','정승기','scrypt:32768:8:1$CvsAWzzruVlwCWdM$aeba71e9211b108ae0a62ce45dffbe6d810a984ee605a6ab657d4b8e932bc88559fa4bce88f754ca2bb2311acdb7e5ef8c7f72010f9d340766be643c20a784ba','작업자');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `violations`
--

DROP TABLE IF EXISTS `violations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `violations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `violation_type` varchar(50) NOT NULL,
  `detected_at` datetime DEFAULT current_timestamp(),
  `area_id` int(11) DEFAULT NULL,
  `image_path` varchar(255) DEFAULT NULL,
  `is_checked` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_area_id` (`area_id`),
  CONSTRAINT `fk_violations_area` FOREIGN KEY (`area_id`) REFERENCES `areas` (`area_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `violations`
--

LOCK TABLES `violations` WRITE;
/*!40000 ALTER TABLE `violations` DISABLE KEYS */;
/*!40000 ALTER TABLE `violations` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-05-10  5:40:15
