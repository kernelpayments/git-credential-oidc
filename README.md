# git-credential-oidc

## Getting started

Install git-credential-oidc from source
```
go get github.com/KernelPay/git-credential-oidc
```

Configure git to use git-credential-oidc for your domain.

```
git config --global credential.https://git.example.com.helper oidc
```

Then login.

```
git credential-oidc login --issuer-url=https://accounts.google.com --client-id=XXX --client-secret=ZZZ
```

That's it! You can now use all `git` commands normally, and you'll be using OIDC authentication.

```
git clone https://git.example.com/MrDeveloper/SomeProject
```
