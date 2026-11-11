# VulnArena

VulnArena is a collection of isolated, reproducible security labs based on real products and vulnerabilities. Labs are intended for local or explicitly authorized environments; vulnerable services must not be exposed publicly or connected to production systems or real customer data.

## Current lab

### MinIO CVE-2023-28432

The first lab reproduces unauthenticated information disclosure in a three-node MinIO deployment.

- [中文实验记录](labs/minio/CVE-2023-28432/README.zh-CN.md)
- [English lab report](labs/minio/CVE-2023-28432/README.md)
- [Nuclei template](labs/minio/CVE-2023-28432/nuclei-template.yaml)
- [Python request and matcher reproduction](labs/minio/reproduce_cve_2023_28432.py)
- [Minimal raw request script](labs/minio/request_minio_verify.py)
- [Compose configuration](labs/minio/CVE-2023-28432/docker-compose.yml)

The Compose file binds the API and Console to `127.0.0.1` and requires `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` to be supplied through the environment. Runtime object-store data under `labs/minio/CVE-2023-28432/mnt/` is ignored by Git.

Read the lab report before starting the intentionally vulnerable service. The scripts can print sensitive values returned by the vulnerable endpoint; keep their output local and never commit it.
