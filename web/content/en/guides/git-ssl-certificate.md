---
title: Git and SSL certificates
seoTitle: "Git SSL certificate problem: add a CA to Git's bundle"
description: "Fix git SSL certificate problem: unable to get local issuer certificate. Which CA bundle each git reads, Schannel, and the command to add a root."
lead: "Git over HTTPS trusts the bundle it was built or configured with. On Windows that is often Git's own bundle, not the Windows store."
---

## Which list git reads

Git hands HTTPS to curl, and trusts the list curl was given. Git for Windows ships its own bundle, `ca-bundle.crt` inside its installation, and reads it unless `http.sslBackend` is set to `schannel`, which makes it use the Windows store instead ([git-config documentation](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslBackend)). `http.sslCAInfo` in a git configuration file, or `GIT_SSL_CAINFO` in the environment, points git at another file ([git-config documentation](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslCAInfo)).

A company root in the Windows store therefore reaches the browser and not git, which is why git fails with [unable to get local issuer certificate](/errors/unable-to-get-local-issuer-certificate/) while the browser connects.

## See which file each git reads

```
certdoctor https://git.example.com/
```

The trust matrix has a row for every `git` it finds, with the file it reads, whether that file trusts the chain, and the command that adds the root:

```
      git C:\Program Files\Git\cmd\git.exe does NOT trust the presented chain (120
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: cmd /c copy /b "C:\Program Files\Git\ucrt64\etc\ssl\certs\ca-bundle.crt"+"<certificate.pem>" "C:\Program Files\Git\ucrt64\etc\ssl\certs\ca-bundle.crt"
```

`L0` shows whether `GIT_SSL_CAINFO` or `GIT_SSL_CAPATH` is set, and the row reads git's own configuration the way git does.

## Add the root

The command appends the certificate to the end of the bundle git reads - `cmd /c copy /b` on Windows, `cat ... >>` on Linux and macOS - and leaves every certificate already in it. Replace `<certificate.pem>` with the full path of the root certificate in PEM form, and run it with administrator rights when the row says so.

Reinstalling or updating Git rewrites its bundle and drops what you appended, and the row says that too. On Windows, switching git to Schannel with `git config --global http.sslBackend schannel` is the other way: git then trusts what the Windows store trusts, including a company root IT already put there.

## What not to do

`git config http.sslVerify false` turns off certificate checks for every repository it applies to.
