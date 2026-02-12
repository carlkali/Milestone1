-- MySQL dump 10.13  Distrib 8.0.36, for Win64 (x86_64)
--
-- Host: localhost    Database: milestone1
-- ------------------------------------------------------
-- Server version	8.4.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login_attempts`
--

DROP TABLE IF EXISTS `login_attempts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `login_attempts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(190) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
  `success` tinyint(1) NOT NULL DEFAULT '0',
  `attempted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_email_time` (`email`,`attempted_at`),
  KEY `idx_ip_time` (`ip_address`,`attempted_at`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_attempts`
--

LOCK TABLES `login_attempts` WRITE;
/*!40000 ALTER TABLE `login_attempts` DISABLE KEYS */;
INSERT INTO `login_attempts` VALUES (1,'test@dlsu.edu.ph','::1',1,'2026-02-03 04:20:58'),(2,'admin@site.local','::1',0,'2026-02-03 04:21:25'),(3,'admin@site.local','::1',0,'2026-02-03 04:22:02'),(4,'admin@site.local','::1',1,'2026-02-03 04:26:05'),(5,'test@dlsu.edu.ph','::1',1,'2026-02-03 05:07:39'),(6,'test@dlsu.edu.ph','::1',0,'2026-02-03 05:11:38'),(7,'test@dlsu.edu.ph','::1',1,'2026-02-03 05:11:44'),(8,'admin@site.local','::1',1,'2026-02-03 05:20:13'),(9,'admin@site.local','::1',1,'2026-02-03 05:29:49'),(10,'test@dlsu.edu.ph','::1',1,'2026-02-03 05:30:13'),(11,'test@dlsu.edu.ph','::1',0,'2026-02-04 06:04:03'),(12,'admin@site.local','::1',1,'2026-02-04 06:04:20'),(13,'test@dlsu.edu.ph','::1',0,'2026-02-04 06:04:37'),(14,'admin@site.local','::1',1,'2026-02-04 06:05:54'),(15,'test@dlsu.edu.ph','::1',1,'2026-02-04 06:06:04'),(16,'test2@gmail.com','::1',1,'2026-02-12 05:41:23'),(17,'admin@site.local','::1',1,'2026-02-12 05:43:05'),(18,'admin@site.local','::1',1,'2026-02-12 07:38:32'),(19,'alexpereira@gmail.com','::1',1,'2026-02-12 08:21:04'),(20,'jonjones@gmail.com','::1',0,'2026-02-12 08:23:39'),(21,'jonjones@gmail.com','::1',1,'2026-02-12 08:23:40'),(22,'jonjones@gmail.com','::1',1,'2026-02-12 08:23:50'),(23,'jonjones@gmail.com','::1',0,'2026-02-12 08:24:03'),(24,'jonjones@gmail.com','::1',1,'2026-02-12 08:24:04'),(25,'jonjones@gmail.com','::1',1,'2026-02-12 08:24:08'),(26,'alexpereira@gmail.com','::1',0,'2026-02-12 08:24:19'),(27,'alexpereira@gmail.com','::1',0,'2026-02-12 08:24:22'),(28,'alexpereira@gmail.com','::1',0,'2026-02-12 08:24:24'),(29,'alexpereira@gmail.com','::1',0,'2026-02-12 08:24:26'),(30,'alexpereira@gmail.com','::1',0,'2026-02-12 08:24:28'),(31,'alexpereira@gmail.com','::1',0,'2026-02-12 08:53:38'),(32,'jonjones@gmail.com','::1',0,'2026-02-12 09:08:18'),(33,'jonjones1@gmail.com','::1',0,'2026-02-12 09:08:23'),(34,'jonjones1@gmail.com','::1',0,'2026-02-12 09:08:24'),(35,'jonjones1@gmail.com','::1',0,'2026-02-12 09:08:26'),(36,'jonjones1@gmail.com','::1',0,'2026-02-12 09:08:27'),(37,'jonjones1@gmail.com','::1',0,'2026-02-12 09:08:29'),(38,'jonjones@gmail.com','::1',0,'2026-02-12 09:08:59'),(39,'jonjones@gmail.com','::1',0,'2026-02-12 09:09:02'),(40,'jonjones@gmail.com','::1',0,'2026-02-12 09:09:05'),(41,'jonjones@gmail.com','::1',0,'2026-02-12 09:09:08'),(42,'jonjones@gmail.com','::1',1,'2026-02-12 09:19:43'),(43,'jonjones@gmail.com','::1',1,'2026-02-12 09:19:53'),(44,'jonjones@gmail.com','::1',0,'2026-02-12 09:19:57');
/*!40000 ALTER TABLE `login_attempts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `full_name` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(190) COLLATE utf8mb4_unicode_ci NOT NULL,
  `phone` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('user','admin') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'user',
  `profile_photo` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `uniq_users_phone` (`phone`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'Default Admin','admin@site.local','0000000000','$2y$10$/1qT/WK97OopeFXpliyUZ..ypbVWTvifjckJBOEpf2z.CMJzpJXR2','admin',NULL,'2026-02-03 04:02:12');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-02-12 17:37:51