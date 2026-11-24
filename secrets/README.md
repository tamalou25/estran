# Clés personnelles

Ce dossier reçoit les clés que **vous** fournissez pour les sources optionnelles. Tout ce
qu'il contient est ignoré par git (sauf ce fichier) et n'entre dans aucune image Docker. Il
est monté en lecture seule dans le seul conteneur `collector`.

Les mots de passe de la base ne sont pas ici : ils sont générés automatiquement.

## abuse.ch ThreatFox

1. Créer un compte gratuit sur <https://auth.abuse.ch/> et y copier la clé (« Auth-Key »).
2. Créer le fichier `secrets/abusech_auth_key` contenant uniquement cette clé.
3. Relancer le collecteur : `docker compose up -d --force-recreate collector`

Sans ce fichier, la source reste inactive et rien n'est demandé à abuse.ch.

Conditions d'abuse.ch, à respecter : usage non lucratif, pas de redistribution des données,
pas d'entraînement de modèle d'IA. Un usage commercial exige un abonnement.

Sous Linux, le conteneur tourne sous un autre utilisateur que le vôtre : le fichier doit lui
être lisible (`chmod 644 secrets/abusech_auth_key`).
