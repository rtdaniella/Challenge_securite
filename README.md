# Challenge Sécurité

Ce projet se concentre sur l'analyse de sécurité et la gestion des règles de pare-feu dans un environnement hybride. Les objectifs principaux sont :

- Analyse et fouille de données des logs de pare-feu
- Détection d'intrusions et analyse de sécurité

## Installation et lancement du projet

### Prérequis
- Git
- Docker
- Docker Compose

### Étapes d'installation

1. Cloner le projet
```bash
git clone https://github.com/rtdaniella/Challenge_securite.git
cd Challenge_securite
```

2. Lancer le projet avec Docker Compose
```bash
docker-compose up -d
```

Cette commande va:
- Construire les images nécessaires
- Créer et démarrer les conteneurs en mode détaché
- Configurer le réseau entre les services

### Arrêt du projet
Pour arrêter les services:
```bash
docker-compose down
```

### Accès à l'application
Une fois lancée, l'application sera accessible à l'adresse:
[http://localhost:8501/](http://localhost:8501/)