# etubeapi

`etubeapi` is a small CLI tool that allows for interacting with Shimano's E-Tube API.

## Installation 👷

`etubeapi` can be installed using `pip`.

```console
$ pip install etubeapi
```

## Usage 🧑‍💻

Run `etubeapi --help` to see the help and all available commands.

```console
$ etubeapi --help
                                                                                  
 Usage: etubeapi [OPTIONS] COMMAND [ARGS]...                                      
                                                                                  
 Operations for scraping and retrieving Shimano E-Tube firmware.                  
                                                                                  
╭─ Options ──────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.        │
│ --show-completion             Show completion for the current shell, to copy   │
│                               it or customize the installation.                │
│ --help                        Show this message and exit.                      │
╰────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────╮
│ fw   Firmware                                                                  │
╰────────────────────────────────────────────────────────────────────────────────╯
```

### Downloading Previously Scraped Firmware

```console
$ curl https://raw.githubusercontent.com/reven-project/etubeapi/refs/heads/master/fw-scraped.yml | etubeapi fw download <DIRECTORY>
```
