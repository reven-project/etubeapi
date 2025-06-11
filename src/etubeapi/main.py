#!/usr/bin/env python3
from __future__ import annotations
import io
import os
from typing import Annotated
from httpx import HTTPStatusError
import typer
import sys
from pathlib import Path
from rich.progress import track
from rich.table import Table
from etubeapi.lib import (
    Firmware,
    get_firmware_list_bisect,
    get_firmware_list,
    get_all_firmware,
    http_get,
    niceprint,
    console,
)
import cattr
import yaml

app = typer.Typer(
    help="Operations for scraping and retrieving Shimano E-Tube firmware."
)

firmware_app = typer.Typer()

app.add_typer(firmware_app, name="fw", help="Firmware")


def is_tty(f: io.TextIOBase | io.RawIOBase | io.BufferedIOBase) -> bool:
    """Returns whether or not an IO object is a tty"""
    try:
        fd = f.fileno()
    except OSError:
        # no fd, not a tty
        return False
    return os.isatty(fd)


def output_fws(fws: list[Firmware]):
    if is_tty(sys.stdout):
        table = Table("filename", "version", "filesize", "md5", "type", "download_url")
        for fw in fws:
            table.add_row(
                fw.filename,
                fw.version,
                str(fw.filesize or "-"),
                fw.md5 or "-",
                fw.type,
                fw.download_url,
            )
        console.print(table)
    else:
        yaml.safe_dump(cattr.unstructure(fws), sys.stdout)


@firmware_app.command("get")
def get_firmware(
    app_version: Annotated[
        str,
        typer.Argument(
            help="Version of the app, or 'any' to use an efficient search in all versions."
        ),
    ],
):
    """Get the firmware for a specific app version."""
    if app_version == "any":
        fws = get_firmware_list_bisect()
    else:
        fws = get_firmware_list(app_version)
    output_fws(fws)


@firmware_app.command("scrape")
def scrape_firmware():
    """Scrape the firmware versions from the Shimano website and API."""
    fws = get_all_firmware()
    output_fws(fws)


@firmware_app.command("download")
def download_firmware(
    dir: Path, file: typer.FileText = sys.stdin, overwrite: bool = False
):
    """Downloads the firmware specified in stdin or --file."""
    fws: list[Firmware] = cattr.structure(yaml.safe_load(file), list[Firmware])

    dir.mkdir(parents=True, exist_ok=True)
    for i, fw in enumerate(
        track(
            fws,
            description="Downloading firmware",
            console=console,
        )
    ):
        file = dir.joinpath(fw.filename)
        if file.exists() and not overwrite:
            continue
        try:
            data = http_get(fw.download_url)
            with file.open("wb") as f:
                f.write(data)
        except HTTPStatusError as e:
            niceprint(
                "WARN",
                f"Unable to download firmware #{i + 1} ({fw.filename}): HTTP Error {e.response.status_code}",
            )


def main():
    app()


if __name__ == "__main__":
    main()
