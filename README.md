# vault-cert-helper

Vault-cert-helper is a simple tool intended to help you provision certificates from on-premises Vault to services running in AWS and GCE (or any other S3 compatible cloud). 

The service running in the cloud need to be able to fetch the certificate from S3. 

Vault-cert-helper will watch if the certificate is older than a half of it's validity time and if so it will request a new one from Vault based on provided CSR and store it S3.

This tool is intended to be deployed as K8s CronJob but can be used as a standalone thing.


# command line options

```yaml
Usage:
  vault-cert-helper [OPTIONS]

Application Options:
  -v, --verbose  Show verbose debug information
  -V, --version  Show version information

Help Options:
  -h, --help     Show this help message
```

By default vault-cert-helper will look for a configuration file named `vault-cert-helper.yaml` in the following locations:
- `$HOME`
- `.`
- `/config`

# configuration file example - K8s ServiceAccount auth

```yaml
# https://github.com/minio/minio-go/blob/master/s3-endpoints.go#L22-L39
endpoint: "http://192.168.99.1:9000"                    # endponit for s3 compatibile services
s3SecretPath: "kv/secret/path"                          # secrets for accessing S3, only v1 Vault KV backend is supported (accessKeyID and secretAccessKey)
authMethod: "sa"                                        # sa - for K8s ServiceAccount, token - for token based
authRole: "vch"                                         # auth role used to login when using K8s ServiceAccount atuh method
authPath: "auth/kubernetes/login"                       # auth path endpoint in vault
vault: "https://192.168.99.1:8200"                      # vault server uri
pkiPath: "pki/sign/woop.sh"                             # pki path
ttl: "1m"                                               # default ttl for reqested certs 
caCert: "/etc/ssl/certs/planet_express_ca.pem"          # path to custom CA Cert file
pkiSpec:                                                # pki spec
  woop:                                                 # custom name
    csr: "s3://some/long/name/woop.sh.csr"              # path to CSR on S3 bucket
    cert: "s3://some/long/name/woop.sh.pem"             # path to CERT on S3 bucket
    ttl: "1m"                                           # ttl for that cert (overwrite default ttl)
  zoidberg:
    csr: "s3://some/long/name/zoidberg.woop.sh.csr"
    cert: "s3://some/long/name/zoidberg.woop.sh.pem"
  zoidberg2:
    csr: "s3://some/long/name/zoidberg2.woop.sh.csr"
    cert: "s3://some/long/name/zoidberg2.woop.sh.pem"
    pkiPath: "pki/sign/woop.sh"                         # path to custom pki role
```


# configuration file example - Vault token
```yaml
# https://github.com/minio/minio-go/blob/master/s3-endpoints.go#L22-L39
endpoint: "http://192.168.99.1:9000"                    # endponit for s3 compatibile services
s3SecretPath: "kv/secret/path"                          # secrets for accessing S3, only v1 Vault KV backend is supported (accessKeyID and secretAccessKey)
authMethod: "token"                                     # sa - for K8s ServiceAccount, token - for token based  
token: "8cc8ddf5-063c-6a85-9971-7a50e9b72811"           # vault token, can by also in env VAULT_TOKEN
vault: "https://192.168.99.1:8200"                      # vault server uri
pkiPath: "pki/sign/woop.sh"                             # path to default pki role
ttl: "1m"                                               # default ttl for reqested certs 
caCert: "/etc/ssl/certs/planet_express_ca.pem"          # path to custom CA Cert file
pkiSpec:                                                # pki spec
  woop:                                                 # custom name
    csr: "s3://some/long/name/woop.sh.csr"              # path to CSR on S3 bucket
    cert: "s3://some/long/name/woop.sh.pem"             # path to CERT on S3 bucket
    ttl: "1m"                                           # ttl for that cert (overwrite default ttl)
  zoidberg:
    csr: "s3://some/long/name/zoidberg.woop.sh.csr"
    cert: "s3://some/long/name/zoidberg.woop.sh.pem"
  zoidberg2:
    csr: "s3://some/long/name/zoidberg2.woop.sh.csr"
    cert: "s3://some/long/name/zoidberg2.woop.sh.pem"
    pkiPath: "pki/sign/woop.sh"                         # path to custom pki role
```

# enviroment variables 

- all vault environment variables can be used https://www.vaultproject.io/docs/commands/index.html#environment-variables
- each value in the config file can be overwritten by environment variable by using `VCH_` prefix and config field name. Variables name needs to be all uppercase.

# example AWS S3 policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": [
                "arn:aws:s3:::some/long/name/woop.sh.csr",
                "arn:aws:s3:::some/long/name/zoidberg.woop.sh.csr",
                "arn:aws:s3:::some/long/name/zoidberg2.woop.sh.csr",
                "arn:aws:s3:::some/long/name/"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::some/long/name/woop.sh.pem",
                "arn:aws:s3:::some/long/name/zoidberg.woop.sh.pem",
                "arn:aws:s3:::some/long/name/zoidberg2.woop.sh.pem",                
                "arn:aws:s3:::some/long/name/"
            ]
        }
    ]
}
```
