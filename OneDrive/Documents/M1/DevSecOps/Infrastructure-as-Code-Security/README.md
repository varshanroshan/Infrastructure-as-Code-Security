# Infrastructure as Code Security — Sujet 07

> Projet BAC+4 — Jedy Formation | DevSecOps | 2025-2026

Ce projet démontre comment **détecter et corriger des vulnérabilités de sécurité dans du code Terraform (IaC)** à l'aide de l'outil d'analyse statique **Checkov** et d'un pipeline **GitHub Actions**.

## Objectif du projet

Illustrer le concept de **"Security as Code"** en comparant deux configurations Terraform AWS :
- `vulnerable/` — Code intentionnellement vulnérable (à des fins pédagogiques)
- `secure/` — Version corrigée respectant les bonnes pratiques CIS AWS

---

## Structure du projet

```
Infrastructure-as-Code-Security/
├── .github/
│   └── workflows/
│       └── iac-security.yml   # Pipeline CI/CD GitHub Actions
├── vulnerable/
│   └── main.tf                # Terraform avec 4 types de vulnérabilités
├── secure/
│   └── main.tf                # Terraform sécurisé (version corrigée)
└── README.md
```

---

## Vulnérabilités simulées

| # | Ressource AWS | Vulnérabilité | ID Checkov | Sévérité | Correction |
|---|---------------|---------------|------------|----------|------------|
| 1 | S3 Bucket | ACL `public-read` — bucket exposé sur internet | `CKV_AWS_20` | HIGH | `aws_s3_bucket_public_access_block` + ACL privée |
| 2 | S3 Bucket | Pas de chiffrement côté serveur | `CKV_AWS_19` | HIGH | `aws_s3_bucket_server_side_encryption_configuration` avec AES256 |
| 3 | S3 Bucket | Versioning désactivé | `CKV_AWS_52` | MEDIUM | `versioning_configuration { status = "Enabled" }` |
| 4 | Security Group | SSH (port 22) ouvert sur `0.0.0.0/0` | `CKV_AWS_24` | CRITICAL | Aucune règle SSH ouverte depuis internet |
| 5 | Security Group | RDP (port 3389) ouvert sur `0.0.0.0/0` | `CKV_AWS_25` | CRITICAL | Uniquement ports 80/443 autorisés |
| 6 | RDS | Mot de passe en clair dans le code | `CKV_AWS_17` | CRITICAL | `password = var.db_password` (variable sensible) |
| 7 | RDS | `storage_encrypted = false` | `CKV_AWS_16` | HIGH | `storage_encrypted = true` |
| 8 | RDS | `publicly_accessible = true` | `CKV_AWS_17` | CRITICAL | `publicly_accessible = false` |
| 9 | RDS | `backup_retention_period = 0` | `CKV_AWS_129` | MEDIUM | `backup_retention_period = 7` |
| 10 | IAM Policy | `Action = "*"` et `Resource = "*"` | `CKV_AWS_62` | CRITICAL | Actions minimales sur ressource spécifique |
| 11 | IAM User | Politique attachée directement à l'utilisateur | `CKV_AWS_40` | MEDIUM | Politique attachée à un rôle IAM |

---

## Pipeline CI/CD

Le workflow GitHub Actions (`.github/workflows/iac-security.yml`) comprend 3 jobs :

```
push/PR → main
    │
    ├── [1] checkov-vulnerable   → Scan informatif (NON bloquant)
    │                              Les échecs sont attendus (vulns intentionnelles)
    │
    ├── [2] checkov-secure       → Gate qualité (BLOQUANT)
    │                              Échec = régression de sécurité à corriger
    │
    └── [3] security-summary     → Rapport comparatif des deux scans
                                   Artifacts JSON uploadés (30 jours)
```

### Logique de blocage

| Répertoire | Comportement pipeline | Raison |
|-----------|----------------------|--------|
| `vulnerable/` | `|| true` — non bloquant | Vulnérabilités **intentionnelles** pour la démo |
| `secure/` | Bloque si échec Checkov | Toute régression doit être corrigée |

---

## Lancer la démo en local

### Prérequis

- Python 3.8+ installé
- (Optionnel) Terraform CLI pour valider la syntaxe

### Installation de Checkov

```bash
pip install checkov
```

### Scanner le code vulnérable

```bash
# Scan compact (résumé)
checkov -d vulnerable/ --compact

# Scan avec rapport JSON
checkov -d vulnerable/ --output json --output-file-path ./reports

# Scanner un fichier spécifique
checkov -f vulnerable/main.tf --compact
```

**Résultat attendu :** ≥ 10 failles détectées (FAILED)

### Scanner le code sécurisé

```bash
checkov -d secure/ --compact
```

**Résultat attendu :** Toutes les règles passent (PASSED)

### Comparer les deux versions

```bash
# Vulnérable
echo "=== VULNÉRABLE ===" && checkov -d vulnerable/ --compact --quiet

# Sécurisé
echo "=== SÉCURISÉ ===" && checkov -d secure/ --compact --quiet
```

---

## Explications techniques

### Qu'est-ce que Checkov ?

[Checkov](https://www.checkov.io/) est un outil SAST (Static Application Security Testing) open-source pour l'IaC. Il analyse les fichiers Terraform, CloudFormation, Kubernetes, Dockerfile, etc. et les compare à des règles de sécurité basées sur :

- **CIS AWS Foundations Benchmark**
- **AWS Well-Architected Framework**
- **NIST SP 800-53**
- **SOC2**

### Principe du moindre privilège (IAM)

```hcl
# MAUVAIS : accès administrateur complet
Action   = "*"
Resource = "*"

# BON : accès minimal sur ressource spécifique
Action   = ["s3:GetObject", "s3:ListBucket"]
Resource = [aws_s3_bucket.my_bucket.arn]
```

### Gestion des secrets

```hcl
# MAUVAIS : secret hardcodé
password = "MonMotDePasse123!"

# BON : variable sensible (injectée via env ou secrets manager)
password  = var.db_password
sensitive = true
```

---

## Auteurs

| Membre | Rôle |
|--------|------|
| Varshanroshan | DevSecOps Engineer |

**Formation :** BAC+4 DevSecOps — Jedy Formation
**Sujet :** 07 — Infrastructure as Code Security
**Année :** 2025-2026

---

## Références

- [Checkov Documentation](https://www.checkov.io/1.Welcome/What%20is%20Checkov.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [OWASP IaC Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
