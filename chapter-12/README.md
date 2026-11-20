# Chapter 12: Database Security and the CIA Triad

These labs demonstrate MongoDB authentication and least-privilege RBAC, TLS for
connections in transit, and field-level redaction with a read-only view. They
use a local, disposable MongoDB instance and synthetic employee data.

## Prerequisites

- MongoDB Server and `mongosh`
- Bash and OpenSSL for Activities 1 and 2 (Git Bash or WSL on Windows)
- Python 3 and PyMongo for Activity 3 (`python -m pip install pymongo`)

Do not use the example users, data, or self-signed certificates for production.

## Activity 1: Authentication and RBAC

Start a local MongoDB instance with authorization enabled, using a disposable
data directory:

```bash
mongod --auth --dbpath ./mongo-data --bind_ip 127.0.0.1 --port 27017
```

In another terminal, bootstrap the first administrator. MongoDB's localhost
exception permits this before the first user exists:

```bash
mongosh --host 127.0.0.1 --port 27017 admin
```

At the `mongosh` prompt:

```javascript
db.createUser({
  user: "lab_admin",
  pwd: passwordPrompt(),
  roles: [{ role: "root", db: "admin" }]
})
```

Exit the shell, then run the setup and verification script from the workspace
root. It prompts for the administrator and each application user's password:

```bash
MONGOSH_ADMIN_USER=lab_admin bash chapter-12/lab_01_rbac_setup.sh
```

The script grants `analyst` read access to `nosql_labs` and `bookstore`,
`app_writer` read/write access only to `nosql_labs`, and `log_writer` read
access to `nosql_labs` plus insert/update access to its `logs` collection.
It then checks permitted operations and confirms that an analyst write and an
`app_writer` read from `bookstore` are rejected. It also confirms that
`log_writer` can insert/update `logs` but cannot write another collection or
delete from `logs`.

## Activity 2: TLS / Encryption in Transit

Generate a local CA and a server certificate with localhost SANs:

```bash
bash chapter-12/lab_02_tls_setup.sh
```

The script prints the `mongod` command to start a TLS-only local server. Run
that command in a separate terminal. The generated `ca.crt` is public; protect
the private keys and combined PEM files (`ca.key`, `server.key`, `server.pem`,
`client.key`, and `client.pem`) and do not commit them. The certificate chain is:

```text
ca.crt (self-signed lab CA)
  ├── signs server.crt (subject localhost; SAN localhost and 127.0.0.1)
  │     └── paired with server.key in server.pem for mongod
  └── signs client.crt (clientAuth)
        └── paired with client.key in client.pem for PyMongo
```

With the TLS-only server running, this plaintext test should fail:

```bash
mongosh --host 127.0.0.1 --port 27017 --eval 'db.runCommand({ ping: 1 })'
```

The TLS connection should succeed:

```bash
mongosh 'mongodb://127.0.0.1:27017/?tls=true&tlsCAFile=chapter-12/tls/ca.crt' \
  --eval 'db.runCommand({ ping: 1 })'
```

PyMongo verification (adjust the CA path if `TLS_DIR` was customized):

```python
from pymongo import MongoClient

client = MongoClient(
    "mongodb://127.0.0.1:27017/?directConnection=true",
    tls=True,
    tlsCAFile="chapter-12/tls/ca.crt",
    tlsCertificateKeyFile="chapter-12/tls/client.pem",
)
print(client.admin.command("ping"))
client.close()
```

The client certificate is signed by the lab CA and sent by PyMongo. The
printed `--tlsAllowConnectionsWithoutCertificates` option makes it optional
for other TLS clients; remove that option to require client certificates for
all connections.

## Activity 3: Field-Level Redaction with a View

Run the Python demo against a local MongoDB instance. Set `MONGODB_ADMIN_URI`
if the server requires authentication; the account must be able to create
views, roles, and users in the `chapter12_security_lab` database.

```bash
python chapter-12/rbac_field_redaction.py
```

The script seeds synthetic records, creates `employees_safe` with SSNs masked
to `***-**-1234` and `salary` removed, and creates two test users. `safe_viewer`
can read only the view; `hr_user` can read the source collection. The script
queries as each user and checks that the restricted user cannot read
`employees`.

The CIA triad maps to these exercises as follows: RBAC, TLS, and the view
protect confidentiality; restricting write actions supports integrity; and
availability is an important separate concern (for example, replica sets and
backups) not configured by these local labs.
