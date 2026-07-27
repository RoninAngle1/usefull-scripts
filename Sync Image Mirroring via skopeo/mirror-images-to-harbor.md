
# mirror-images-to-harbor.sh

## Purpose

Mirrors images listed in the inventory into Harbor using Skopeo.

## Dependencies

- skopeo
- flock
- awk
- sed
- grep
- sort
- wc
- tr
- mktemp

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| HARBOR_REGISTRY | Harbor hostname | regdc.negahcloud.ir |
| HARBOR_PROJECT | Harbor project | public |
| HARBOR_USERNAME | Harbor username | required |
| HARBOR_PASSWORD | Harbor password | required |
| PRESERVE_SOURCE_REGISTRY | Keep original registry path | true |
| PUBLIC_REGISTRY_ALLOWLIST | Allowed source registries | docker.io,... |
| REGISTRY_DENYLIST | Blocked registries | localhost,127.0.0.1 |
| COPY_ALL_ARCHITECTURES | Mirror all architectures | true |
| VERIFY_EXISTING_DIGEST | Compare digests | true |
| OVERWRITE_DIGEST_MISMATCH | Replace mismatched images | false |
| MIRROR_DIGEST_ONLY_IMAGES | Mirror digest-only images | true |
| FAIL_ON_TAG_DIGEST_CONFLICT | Stop on conflicting tags | true |
| SOURCE_AUTHFILE | Source registry auth file | empty |
| SOURCE_CREDS | Source credentials | empty |
| SOURCE_TLS_INSECURE | Disable source TLS verify | false |
| HARBOR_TLS_INSECURE | Disable Harbor TLS verify | false |
| HARBOR_NO_PROXY | Access Harbor directly | false |
| MAX_RETRIES | Retry attempts | 4 |
| RETRY_DELAY_SECONDS | Delay between retries | 10 |
| LOG_DIR | Log directory | /var/log/k8s-image-mirror |
| LOG_FILE | Log file | harbor-mirror.log |
| LOCK_FILE | Lock file | /var/run/k8s-image-mirror.lock |
| HTTP_PROXY/HTTPS_PROXY/NO_PROXY | Standard proxy settings | inherited |

## Sample .env.example

```env
HARBOR_REGISTRY=harbor.example.com
HARBOR_PROJECT=public
HARBOR_USERNAME=admin
HARBOR_PASSWORD=change-me
PRESERVE_SOURCE_REGISTRY=true
COPY_ALL_ARCHITECTURES=true
VERIFY_EXISTING_DIGEST=true
OVERWRITE_DIGEST_MISMATCH=false
SOURCE_TLS_INSECURE=false
HARBOR_TLS_INSECURE=false
MAX_RETRIES=4
RETRY_DELAY_SECONDS=10
```

## Sample Execution

```bash
export $(grep -v '^#' .env | xargs)

./mirror-images-to-harbor.sh k8s-images.txt
```

## Sample Log Output

```text
INFO MIRROR_STARTED
INFO CHECKING_IMAGE source=docker.io/library/nginx:1.25.2
INFO IMAGE_PUSHED_SUCCESSFULLY
INFO MIRROR_SUMMARY pushed=45 failed=0
```

## Architecture

```text
Inventory File
      |
      v
Normalize
      |
Filter Registries
      |
Inspect Source
      |
Inspect Harbor
      |
skopeo copy
      |
Verify Digest
      |
Summary
```
