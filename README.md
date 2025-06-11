# 📚 SmartPlanner API

SmartPlanner est une plateforme complète de gestion scolaire construite avec **FastAPI**. Elle permet de gérer les établissements, enseignants, étudiants, emplois du temps, ressources, permissions et rôles dans un environnement moderne, évolutif et sécurisé.

---

## 🚀 Fonctionnalités principales

- 🔐 Authentification et gestion des utilisateurs
- 🧑‍🏫 Gestion des enseignants et de leur disponibilité
- 🧑‍🎓 Gestion des étudiants et de leurs profils
- 🏫 Gestion des établissements scolaires
- 🗓️ Gestion des cours, salles, emplois du temps, réservations et événements
- 🔄 Permissions et rôles configurables
- 🌐 API RESTful avec documentation Swagger et Redoc
- 🌍 Support multilingue intelligent avec traduction automatique des réponses
- 🛠️ Architecture modulaire et extensible
- 📦 Support d’outils modernes : Docker, Alembic, Uvicorn, SQLAlchemy

---

## ⚙️ Prérequis

- Python ≥ 3.11
- PostgreSQL
- Git (optionnel)
- Docker (optionnel pour conteneurisation)

---

## 🛠️ Installation & Démarrage

```bash
# Cloner le dépôt
git clone https://your-git-repository-url
cd SmartPlanner

# Créer et activer un environnement virtuel
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sous Windows

# Installer les dépendances
pip install -r requirements.txt
```

Configurer le fichier `.env` avec vos variables :

```
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/smartplanner
SECRET_KEY=your-secret-key
```

---

## 🗃️ Migrations de base de données

Utilisation d’Alembic pour versionner le schéma :

```bash
# Générer une migration initiale
alembic revision --autogenerate -m "Initial migration"

# Appliquer toutes les migrations
alembic upgrade head

# Vérifier l’état des migrations
alembic current

# Revenir à une version précédente
alembic downgrade -1

# Créer une migration manuellement
alembic revision -m "Description de la migration"
```

---

## ▶️ Lancer le projet

```bash
uvicorn src.main:app --reload
```

Accéder à la documentation :

- Swagger UI : http://localhost:8000/docs
- Redoc : http://localhost:8000/redoc

---

## 📁 Structure du projet

```
src/
├── api/                  # Routeurs FastAPI
├── models.py             # Modèles ORM SQLAlchemy
├── schemas.py            # Schémas Pydantic
├── services.py           # Logique métier
├── enums.py              # Enums partagés
├── main.py               # Point d'entrée principal
├── security.py           # Authentification & autorisation
├── init_directories.py   # Initialisation de répertoires requis
└── ...
```

---

## 🧠 Bonnes pratiques

- Séparation claire des responsabilités (services, modèles, routes)
- Gestion d’erreurs centralisée
- Utilisation d'`AsyncSession` pour des performances optimales
- Pattern "Dependency Injection" avec `Depends`
- Utilisation de `joinedload` pour optimiser les requêtes ORM
- Support de la traduction automatique des réponses via `googletrans`

---

## ✨ À venir

- Intégration OAuth (Google, GitHub)
- Notifications par e-mail / SMS
- Tableau de bord d'administration
- Tests automatisés avec Pytest
- Monitoring (Sentry, Prometheus)

---

## 👨‍💻 Auteur

Développé par l'équipe SmartPlanner — [support@smartschoolplanner.com](mailto:support@smartschoolplanner.com)

---

## 📝 Licence

MIT License

taskkill /F /IM python.exe
