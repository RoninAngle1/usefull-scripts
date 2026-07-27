
# Kubernetes Image Inventory & Harbor Mirror

## Overview

This repository contains two Bash scripts that work together:

1. **collect-k8s-images.sh** – Discovers every container image cached on every Kubernetes node.
2. **mirror-images-to-harbor.sh** – Reads the inventory and mirrors the images into a Harbor registry.

## Architecture

```text
+--------------------+
| Kubernetes Cluster |
+---------+----------+
          |
          | kubectl get nodes -o json
          v
+--------------------------+
| collect-k8s-images.sh    |
+--------------------------+
          |
          | k8s-images.txt
          v
+--------------------------+
| mirror-images-to-harbor  |
+--------------------------+
          |
          | skopeo copy
          v
+--------------------------+
| Harbor Registry          |
+--------------------------+
```

## Workflow

1. Collect node image inventory.
2. Review generated inventory.
3. Configure Harbor environment variables.
4. Mirror images into Harbor.

---

## Sample Skopeo command if you wanted to add another image manually

```
skopeo --debug copy --all \
   --dest-creds "${HARBOR_USERNAME}:${HARBOR_PASSWORD}" \
   docker://python:3.12-slim \
   docker://harbor.example.com/public/docker.io/python:3.12-slim
```
