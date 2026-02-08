# Scan Minecraft Server

Ensemble d'outils Python pour scanner et détecter des serveurs Minecraft en utilisant le protocole natif (handshake + status request). Les scripts récupèrent le **MOTD**, le **nombre de joueurs** en ligne et les **noms des joueurs** connectés.

---

## Prérequis

- **Python 3.7+** (utilise `asyncio`)
- Aucune dépendance externe requise (uniquement des modules standard)

---

## Scripts disponibles

### 1. `ip-range.py` — Scanner une plage d'adresses IP

Ce script scanne une plage d'adresses IP (CIDR ou plage start/end) sur un port donné afin de trouver des serveurs Minecraft actifs.

#### Utilisation

```bash
# Scanner un réseau entier via CIDR
python ip-range.py --cidr 192.168.1.0/24

# Scanner une plage d'IP spécifique
python ip-range.py --start 10.0.0.1 --end 10.0.0.254

# Scanner une seule IP
python ip-range.py --ip 127.0.0.1

# Options avancées
python ip-range.py --cidr 192.168.1.0/24 --port 25565 --concurrency 200 --timeout 3.0
```

#### Options

| Option          | Description                                      | Défaut    |
|-----------------|--------------------------------------------------|-----------|
| `--cidr`        | Plage CIDR à scanner (ex: `192.168.1.0/24`)     | —         |
| `--start`       | IP de début (inclusive)                           | —         |
| `--end`         | IP de fin (inclusive, utilisé avec `--start`)     | —         |
| `--ip`          | IP unique à vérifier                             | —         |
| `--port`        | Port du serveur Minecraft                        | `25565`   |
| `--concurrency` | Nombre de connexions simultanées                 | `200`     |
| `--timeout`     | Délai d'attente en secondes par connexion        | `3.0`     |

---

### 2. `port-range.py` — Scanner une plage de ports sur une IP

Ce script scanne une plage de ports sur une seule adresse IP afin de détecter des serveurs Minecraft qui tourneraient sur des ports non-standard.

#### Utilisation

```bash
# Scanner les ports 25560 à 25600 sur une IP
python port-range.py --ip 13.36.117.199 --start-port 25560 --end-port 25600

# Avec options avancées
python port-range.py --ip 13.36.117.199 --start-port 25500 --end-port 25600 --concurrency 100 --timeout 2.5
```

#### Options

| Option          | Description                                      | Défaut    |
|-----------------|--------------------------------------------------|-----------|
| `--ip`          | Adresse IP ou nom d'hôte à scanner (obligatoire) | —         |
| `--start-port`  | Port de début (obligatoire)                      | —         |
| `--end-port`    | Port de fin (obligatoire)                        | —         |
| `--concurrency` | Nombre de connexions simultanées                 | `200`     |
| `--timeout`     | Délai d'attente en secondes par connexion        | `2.5`     |

---

### 3. `scan.py` — Scanner combiné (plage d'IP + plage de ports)

Ce script combine les deux précédents : il scanne une **plage d'adresses IP** sur une **plage de ports** simultanément. Chaque combinaison IP:port est testée de manière asynchrone.

#### Utilisation

```bash
# Scanner un réseau CIDR sur une plage de ports
python scan.py --cidr 192.168.1.0/24 --start-port 25560 --end-port 25570

# Scanner une plage d'IP sur une plage de ports
python scan.py --start 10.0.0.1 --end 10.0.0.50 --start-port 25565 --end-port 25575

# Scanner une seule IP sur une plage de ports
python scan.py --ip 127.0.0.1 --start-port 25560 --end-port 25600

# Scanner un réseau sur le port par défaut (25565)
python scan.py --cidr 192.168.1.0/24

# Scanner un réseau sur un port unique spécifique
python scan.py --cidr 192.168.1.0/24 --port 25577

# Options avancées
python scan.py --cidr 10.0.0.0/16 --start-port 25560 --end-port 25570 --concurrency 300 --timeout 2.0
```

#### Options

| Option          | Description                                           | Défaut    |
|-----------------|-------------------------------------------------------|-----------|
| `--cidr`        | Plage CIDR à scanner (ex: `192.168.1.0/24`)          | —         |
| `--start`       | IP de début (inclusive)                                | —         |
| `--end`         | IP de fin (inclusive, utilisé avec `--start`)          | —         |
| `--ip`          | IP unique à scanner                                   | —         |
| `--port`        | Port unique à scanner                                 | `25565`   |
| `--start-port`  | Port de début (inclusive)                              | —         |
| `--end-port`    | Port de fin (inclusive)                                | —         |
| `--concurrency` | Nombre de connexions simultanées                      | `200`     |
| `--timeout`     | Délai d'attente par connexion en secondes             | `3.0`     |

> **Note :** Si aucun port n'est spécifié, le port par défaut `25565` est utilisé. Utilisez `--start-port` et `--end-port` pour scanner une plage, ou `--port` pour un port unique.

---

## Informations récupérées

Pour chaque serveur Minecraft détecté, les scripts affichent :

- **IP:Port** — Adresse et port du serveur
- **MOTD** — Message du jour (description du serveur)
- **Joueurs** — Nombre de joueurs en ligne / nombre maximum
- **Échantillon** — Liste des noms de joueurs connectés (si disponible)

## Fonctionnement technique

Les trois scripts utilisent le **protocole Minecraft** natif :

1. **Handshake** (paquet `0x00`) — Établit la connexion avec la version du protocole, l'adresse et le port
2. **Status Request** (paquet `0x00`) — Demande les informations du serveur
3. **Status Response** — Le serveur renvoie un JSON contenant le MOTD, la version et les joueurs

Le tout est exécuté de manière **asynchrone** (`asyncio`) avec un système de sémaphore pour contrôler la concurrence et éviter de surcharger le réseau.
