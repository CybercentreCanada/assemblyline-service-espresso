[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_onenote-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-onenote)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-assemblyline-service-onenote)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-assemblyline-service-onenote)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-onenote)](./LICENSE)

# Espresso Service

This Assemblyline service analyzes Java JAR files. All classes are extracted,
decompiled and analyzed for malicious behavior.

## Service Details

The service extracts all the files from inside the Jar then performs analysis of the different
files for malicious behavior. For all the `.java` files found inside the jar, the service will
run the `CFR Decompiler` tool on it to get back a human readable version of the code.

When a file inside the Jar is noted as potentially malicious, the file is added as a supplementary file
to the results so the analysts can see the content of that file.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Espresso \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-espresso

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Espresso

Ce service Assemblyline analyse les fichiers Java JAR. Toutes les classes sont extraites, décompilées et analysées pour détecter tout comportement malveillant.

## Détails du service

Le service extrait tous les fichiers à l'intérieur de la jarre puis effectue une analyse des différents
fichiers à la recherche d'un comportement malveillant. Pour tous les fichiers `.java` trouvés dans le jar, le service va
exécute l'outil `CFR Decompiler` pour obtenir une version du code lisible par l'homme.

Lorsqu'un fichier contenu dans le jar est considéré comme potentiellement malveillant, il est ajouté en tant que fichier supplémentaire aux résultats afin que les analystes puissent le lire.
aux résultats afin que les analystes puissent voir le contenu de ce fichier.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Il s'agit d'un service d'Assemblyline. Il est optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Espresso \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-espresso

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
