# =============================================================================
# FICHIER VOLONTAIREMENT VULNÉRABLE - À NE PAS UTILISER EN PRODUCTION
# Objectif pédagogique : démonstration des mauvaises pratiques IaC
# Détecté par Checkov (outil d'analyse statique SAST pour Terraform)
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

# =============================================================================
# VULNÉRABILITÉ 1 — CKV_AWS_20 + CKV_AWS_19 + CKV_AWS_52 + CKV_AWS_145
# Bucket S3 public avec ACL "public-read" et sans chiffrement
# Risque : exposition de données sensibles sur internet
# =============================================================================
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-super-vulnerable-bucket-demo"

  # VULN: pas de tags, pas de versioning, pas de logging
  tags = {
    Name = "VulnerableBucket"
  }
}

# VULN CKV_AWS_20 : ACL public-read expose le bucket à tout internet
resource "aws_s3_bucket_acl" "vulnerable_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read" # DANGER : tout le monde peut lire ce bucket !
}

# VULN CKV_AWS_19 : Pas de chiffrement côté serveur
# (absence de aws_s3_bucket_server_side_encryption_configuration)

# VULN CKV_AWS_52 : MFA Delete non activé
resource "aws_s3_bucket_versioning" "vulnerable_versioning" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Disabled" # VULN: versioning désactivé
  }
}

# =============================================================================
# VULNÉRABILITÉ 2 — CKV_AWS_24 + CKV_AWS_25
# Security Group avec tous les ports ouverts vers 0.0.0.0/0
# Risque : accès non restreint à toute l'infrastructure
# =============================================================================
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Security group ouvert sur tous les ports"

  # VULN CKV_AWS_24 : SSH (port 22) ouvert depuis internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # DANGER : SSH ouvert au monde entier !
  }

  # VULN CKV_AWS_25 : RDP (port 3389) ouvert depuis internet
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # DANGER : RDP ouvert au monde entier !
  }

  # VULN : Tous les ports ouverts sur toute plage
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # DANGER : surface d'attaque maximale !
  }

  # VULN : Egress non restreint (acceptable mais combiné c'est risqué)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "VulnerableSG"
  }
}

# =============================================================================
# VULNÉRABILITÉ 3 — CKV_AWS_16 + CKV_AWS_17 + CKV_AWS_129 + CKV_AWS_133
# Instance RDS avec mot de passe en clair, non chiffrée, publiquement accessible
# Risque : compromission de la base de données
# =============================================================================
resource "aws_db_instance" "vulnerable_rds" {
  identifier        = "vulnerable-rds-demo"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "mydb"
  username          = "admin"

  # VULN CKV_AWS_17 : Mot de passe en clair dans le code source !
  # Ce mot de passe sera visible dans le state Terraform et l'historique git
  password = "SuperPassword123!" # DANGER : secret hardcodé !

  # VULN CKV_AWS_16 : Chiffrement du stockage désactivé
  storage_encrypted = false # DANGER : données au repos non chiffrées !

  # VULN CKV_AWS_17 : Base de données accessible depuis internet
  publicly_accessible = true # DANGER : RDS exposé sur internet !

  # VULN CKV_AWS_129 : Pas de période de rétention des backups
  backup_retention_period = 0 # DANGER : pas de backup automatique !

  # VULN CKV_AWS_133 : Pas de protection contre la suppression accidentelle
  deletion_protection = false

  # VULN : Pas de multi-AZ (pas de haute disponibilité)
  multi_az = false

  skip_final_snapshot = true

  tags = {
    Name = "VulnerableRDS"
  }
}

# =============================================================================
# VULNÉRABILITÉ 4 — CKV_AWS_62 + CKV_AWS_40
# IAM Policy avec droits administrateur complets (Action=* Resource=*)
# Risque : escalade de privilèges, compromission totale du compte AWS
# =============================================================================
resource "aws_iam_policy" "vulnerable_policy" {
  name        = "VulnerableAdminPolicy"
  description = "Politique IAM trop permissive - usage pédagogique uniquement"

  # VULN CKV_AWS_62 : Action "*" donne tous les droits AWS à l'entité
  # VULN : Resource "*" s'applique à TOUTES les ressources du compte
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"        # DANGER : accès à TOUS les services AWS !
        Resource = "*"        # DANGER : sur TOUTES les ressources !
      }
    ]
  })
}

# VULN CKV_AWS_40 : Politique attachée directement à un utilisateur IAM
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"
}

resource "aws_iam_user_policy_attachment" "vulnerable_attachment" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.vulnerable_policy.arn
}
