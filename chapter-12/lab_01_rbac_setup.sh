#!/usr/bin/env bash
set -euo pipefail

MONGOSH_BIN="${MONGOSH_BIN:-mongosh}"
MONGO_HOST="${MONGO_HOST:-127.0.0.1}"
MONGO_PORT="${MONGO_PORT:-27017}"
ADMIN_USER="${MONGOSH_ADMIN_USER:-lab_admin}"

if ! command -v "$MONGOSH_BIN" >/dev/null 2>&1; then
  printf 'mongosh was not found. Set MONGOSH_BIN or install MongoDB Shell.\n' >&2
  exit 1
fi

run_as() {
  local username="$1"
  shift
  "$MONGOSH_BIN" --host "$MONGO_HOST" --port "$MONGO_PORT" \
    --username "$username" --authenticationDatabase admin --password \
    --quiet "$@"
}

run_admin() {
  run_as "$ADMIN_USER" "$@"
}

printf 'Creating/updating the lab roles and users. Mongosh will prompt for passwords.\n'
run_admin --eval '
const admin = db.getSiblingDB("admin");
const roleName = "limitedLogWriter";
const roleDefinition = {
  privileges: [
    {
      resource: { db: "nosql_labs", collection: "logs" },
      actions: ["insert", "update"]
    }
  ],
  roles: [{ role: "read", db: "nosql_labs" }]
};

try {
  admin.updateRole(roleName, roleDefinition);
} catch (error) {
  if (error.code !== 31) {
    throw error;
  }
  admin.createRole({ role: roleName, ...roleDefinition });
}

function upsertUser(user, roles) {
  const password = passwordPrompt(`Password for ${user}: `);
  if (admin.getUser(user)) {
    admin.updateUser(user, { pwd: password, roles });
  } else {
    admin.createUser({ user, pwd: password, roles });
  }
}

upsertUser("analyst", [
  { role: "read", db: "nosql_labs" },
  { role: "read", db: "bookstore" }
]);
upsertUser("app_writer", [{ role: "readWrite", db: "nosql_labs" }]);
upsertUser("log_writer", [{ role: roleName, db: "admin" }]);
print("[OK] Roles and users are ready.");
'

printf '\nChecking analyst read access and write denial.\n'
run_as analyst --eval '
db.getSiblingDB("bookstore").getCollection("books").findOne();
try {
  db.getSiblingDB("nosql_labs").getCollection("rbac_probe").insertOne({
    _id: new Date().toISOString(),
    source: "chapter-12 RBAC verification"
  });
  print("[ERROR] analyst write should have failed.");
  quit(1);
} catch (error) {
  if (error.code !== 13) {
    throw error;
  }
  print("[OK] analyst write was correctly rejected.");
}
'

printf '\nChecking app_writer write access and read denial.\n'
run_as app_writer --eval '
db.getSiblingDB("nosql_labs").getCollection("rbac_probe").insertOne({
  _id: new Date().toISOString(),
  source: "chapter-12 RBAC verification"
});
try {
  db.getSiblingDB("bookstore").getCollection("books").findOne();
  print("[ERROR] app_writer read from bookstore should have failed.");
  quit(1);
} catch (error) {
  if (error.code !== 13) {
    throw error;
  }
  print("[OK] app_writer read from bookstore was correctly rejected.");
}
'

printf '\nChecking log_writer collection-scoped permissions.\n'
run_as log_writer --eval '
const logs = db.getSiblingDB("nosql_labs").getCollection("logs");
const logId = new Date().toISOString();
logs.insertOne({ _id: logId, message: "RBAC verification" });
logs.updateOne({ _id: logId }, { $set: { verified: true } });
try {
  db.getSiblingDB("nosql_labs").getCollection("rbac_probe").insertOne({
    _id: new Date().toISOString(),
    source: "chapter-12 RBAC verification"
  });
  print("[ERROR] log_writer insert outside logs should have failed.");
  quit(1);
} catch (error) {
  if (error.code !== 13) {
    throw error;
  }
  print("[OK] log_writer write outside logs was correctly rejected.");
}
try {
  logs.deleteOne({ _id: logId });
  print("[ERROR] log_writer delete from logs should have failed.");
  quit(1);
} catch (error) {
  if (error.code !== 13) {
    throw error;
  }
  print("[OK] log_writer delete was correctly rejected.");
}
'
