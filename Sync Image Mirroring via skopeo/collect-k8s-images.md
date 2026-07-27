
# collect-k8s-images.sh

## Purpose
Collects all cached container images reported by Kubernetes Nodes using the Kubernetes API only.

## Dependencies
- kubectl
- jq
- awk
- sed
- grep
- sort
- mktemp
- wc
- tr

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| KUBECONFIG | Path to kubeconfig | system |
| KUBE_CONTEXT | Kubernetes context | current |
| INCLUDE_DIGEST_ONLY | Include digest-only images | true |

## Output

TSV columns:

1. source_image
2. image_name
3. version
4. digest
5. nodes

## Sample Command

```bash
./collect-k8s-images.sh ./k8s-images.txt
```

## Sample Output

```text
source_image                         image_name                      version digest      nodes
docker.io/library/nginx:1.25.2       docker.io/library/nginx         1.25.2 sha256:abc  worker-01,worker-02
registry.k8s.io/pause:3.9            registry.k8s.io/pause           3.9    sha256:def  master-01
```

## API Flow

```text
kubectl
    |
GET Node objects
    |
status.images
    |
normalize
    |
aggregate
    |
inventory file
```

## Script Flow

1. Validate dependencies.
2. Validate permissions.
3. Query Kubernetes Nodes.
4. Parse `status.images`.
5. Normalize image references.
6. Aggregate duplicate entries.
7. Detect digest conflicts.
8. Write inventory.
