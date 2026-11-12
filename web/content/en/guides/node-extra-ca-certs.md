---
title: NODE_EXTRA_CA_CERTS and NODE_USE_SYSTEM_CA
linkTitle: Node.js and npm
seoTitle: "NODE_EXTRA_CA_CERTS and NODE_USE_SYSTEM_CA explained"
description: "Fix SELF_SIGNED_CERT_IN_CHAIN in Node.js and npm: NODE_USE_SYSTEM_CA to trust the system store, NODE_EXTRA_CA_CERTS to add a root, and which to use."
lead: "Node.js trusts the list it was built with, not the system's. Two variables extend it, and which one you need depends on where your root already is."
---

## Which list Node.js reads

Node.js carries its own list of root authorities, compiled into the binary. It does not read the Windows store or the Linux bundle unless told to. Two environment variables add to its list, and neither removes anything from it ([Node.js documentation](https://nodejs.org/api/cli.html#node_extra_ca_certsfile)):

- `NODE_USE_SYSTEM_CA=1` adds the certificates the operating system trusts. It is read by Node.js from v22.19.0 and v24.6.0 on, and by no v23.
- `NODE_EXTRA_CA_CERTS` names a PEM file whose certificates are added.

Node.js reads both when it starts, so a `node` already running - an editor's language server, a watcher - keeps the old list until it is restarted. npm runs on Node.js, so the variables reach it too.

## See what each node needs

```
certdoctor https://registry.npmjs.org/
```

Every `node` on PATH gets a row, judged by the list that binary trusts. Its command is the first of these that would work:

1. **`NODE_USE_SYSTEM_CA=1`** when the system's own list would close the chain - the usual case when IT already put the company root in the system store. Nothing to download.
2. **An append to the file `NODE_EXTRA_CA_CERTS` names**, when that variable is already set and Node read certificates from it. Setting the variable again would drop that file.
3. **Setting `NODE_EXTRA_CA_CERTS`** to a file with the root, when nothing is set.

On Windows the command is `setx`, which keeps the variable for your account; on Linux and macOS it is `export`, which belongs in your shell's profile to stay:

```
setx NODE_USE_SYSTEM_CA 1
export NODE_USE_SYSTEM_CA=1
```

Open a new terminal afterwards: `setx` reaches only windows opened after it ran.

## What not to do

`NODE_TLS_REJECT_UNAUTHORIZED=0` and `npm config set strict-ssl false` turn off certificate checks altogether. `L0` reads `NODE_TLS_REJECT_UNAUTHORIZED`, so a report shows when somebody already did.
