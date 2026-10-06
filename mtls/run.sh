#!/usr/bin/env bash
# Generates a throwaway CA + server + client keystores with keytool, then runs Mtls.java.
set -euo pipefail
cd "$(dirname "$0")"
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
P=changeit
kt() { keytool -J-Duser.language=en "$@" -storepass $P -keypass $P >/dev/null 2>&1; }
kt -genkeypair -alias ca -dname "CN=lab-ca" -keyalg EC -groupname secp256r1 -ext bc:c -validity 2 -keystore "$D/ca.p12"
kt -exportcert -alias ca -rfc -file "$D/ca.crt" -keystore "$D/ca.p12"
for n in server client; do
  kt -genkeypair -alias $n -dname "CN=$n" -keyalg EC -groupname secp256r1 -ext san=dns:localhost -validity 2 -keystore "$D/$n.p12"
  kt -certreq -alias $n -file "$D/$n.csr" -keystore "$D/$n.p12"
  kt -gencert -alias ca -infile "$D/$n.csr" -outfile "$D/$n.crt" -rfc -ext san=dns:localhost -validity 2 -keystore "$D/ca.p12"
  cat "$D/$n.crt" "$D/ca.crt" > "$D/$n.chain"
  kt -importcert -noprompt -alias ca -file "$D/ca.crt" -keystore "$D/$n.p12"
  kt -importcert -noprompt -alias $n -file "$D/$n.chain" -keystore "$D/$n.p12"
done
kt -importcert -noprompt -alias ca -file "$D/ca.crt" -keystore "$D/trust.p12"
java Mtls.java "$D" $P
