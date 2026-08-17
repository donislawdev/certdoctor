#!/bin/sh
# Mints the three-level chain the no-intermediate bench needs, at startup.
#
# WHAT GOES IN THE REPOSITORY IS THIS SCRIPT. The keys and certificates it
# produces never touch the working tree at all - they are written into a docker
# volume, so "no private key is ever committed" (ADR5) holds by construction
# rather than by a .gitignore pattern somebody could widen. A pattern is a
# promise; a volume is a fact.
#
# THE CHAIN IS THREE LEVELS BECAUSE THE SCENARIO IS ABOUT THE MIDDLE ONE. Root
# signs intermediate, intermediate signs the leaf, and nginx is then handed the
# LEAF ALONE. A client that trusts the root still cannot build a path, because
# the certificate that joins the two is the one nobody sent. Two levels would
# make the scenario impossible to express: there would be nothing to leave out.
#
# EVERYTHING IS REGENERATED ON EVERY START rather than reused when present. A
# bench that half-remembers a previous run is a bench whose failures depend on
# what somebody did yesterday, and this one is supposed to answer the same way on
# a train as in CI.
set -eu

out=/out
step=step

echo "chain: minting into $out"
rm -f "$out"/root.crt "$out"/root.key \
      "$out"/intermediate.crt "$out"/intermediate.key \
      "$out"/leaf.crt "$out"/leaf.key "$out"/bundle.crt

# --no-password --insecure: this key protects nothing. It signs certificates for
# names nobody owns, on a bench that is thrown away. A passphrase here would be
# ceremony that has to be stored somewhere anyway.
$step certificate create "certdoctor testbed root" \
    "$out/root.crt" "$out/root.key" \
    --profile root-ca --no-password --insecure --not-after 8760h

$step certificate create "certdoctor testbed intermediate" \
    "$out/intermediate.crt" "$out/intermediate.key" \
    --profile intermediate-ca \
    --ca "$out/root.crt" --ca-key "$out/root.key" \
    --no-password --insecure --not-after 8760h

$step certificate create "partner.test" \
    "$out/leaf.crt" "$out/leaf.key" \
    --profile leaf \
    --ca "$out/intermediate.crt" --ca-key "$out/intermediate.key" \
    --san partner.test \
    --no-password --insecure --not-after 8760h

# The bundle is written but DELIBERATELY NOT SERVED. It exists so the bench can
# demonstrate the difference on demand - point nginx at this file and the same
# scenario turns into an ordinary working site - and so that anybody reading this
# directory can see that leaving the intermediate out was a choice.
cat "$out/leaf.crt" "$out/intermediate.crt" > "$out/bundle.crt"

# World-readable because nginx runs as another user in another container and
# these protect nothing. Said outright so it does not read as an oversight.
chmod 0644 "$out"/*.crt "$out"/*.key

echo "chain: done"
$step certificate inspect --short "$out/leaf.crt"
