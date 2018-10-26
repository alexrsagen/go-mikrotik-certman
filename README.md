# MikroTik Certificate Manager
Certificate updater for MikroTik routers. Useful for updating Let's Encrypt certificates on a MikroTik router.

## Usage

```
Usage of go-mikrotik-certman:
  -c string
        Configuration file (default "config.json")
```

Check out the sample configuration file and modify it to your needs. By default, the tool will try to load `config.json` in the current working directory. A custom configuration file path can also be provided using the command-line flag `-c`.

**Note that certificate and private key MUST be in PEM format!**