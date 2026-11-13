---
title: Inside a container
seoTitle: Diagnose certificate errors inside a Docker container
description: "Copy the static Linux binary into a container and run it there: the report then describes the container's DNS, proxy and trust stores, not the host's."
lead: "A container is a machine of its own, with its own resolver, its own proxy variables and its own CA bundle. Ask it, not the host."
---

## Why the host's answer is not the container's

An image has its own CA bundle, often older or smaller than the host's, and a company root added to the host never reaches it. Its proxy variables are whatever the image or the run command set, and its resolver is the one the container runtime gave it. That is why the same URL works on the host and fails in the container.

## Copy it in and run it

The command line, `certdoctor`, is one static file on Linux with no C library to depend on, so it runs as it is in Alpine, in Ubuntu and in an image with nothing else in it:

```
docker cp certdoctor my-container:/tmp/certdoctor
docker exec my-container /tmp/certdoctor https://api.example.com/
```

The report then describes the container: its environment variables, its resolvers, its proxy, and every trust store inside it. `L0` says that it runs inside a container.

Take the archive for the container's architecture: `linux_amd64` for x64 images, `linux_arm64` for Arm ones. The [download page](/download/) lists both.

## In a Dockerfile, while you build

The same binary can run in a build stage, to see why a step that downloads something fails:

```
COPY certdoctor /usr/local/bin/certdoctor
RUN certdoctor https://registry.example.com/ || true
```

The `|| true` keeps the build going so you can read the report. Remove the line once the cause is fixed.
