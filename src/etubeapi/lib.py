from __future__ import annotations
from urllib.parse import quote
from dataclasses import dataclass
from typing import Iterable, Union
import json
from httpx import HTTPStatusError, HTTPError, TimeoutException
import unittest
import httpx
import re
import difflib
import time
from functools import cache, total_ordering
from bs4 import BeautifulSoup
from rich.progress import track, Progress
from rich.console import Console
import cattr

console = Console(stderr=True)


IMPERSONATE_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5",
    "cache-control": "max-age=0",
    "priority": "u=0, i",
    "sec-ch-ua": '"Chromium";v="135", "Not-A.Brand";v="8"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


@dataclass(eq=True, frozen=True)
class Firmware:
    filename: str
    version: str
    filesize: int | None
    md5: str | None
    type: str | None
    download_url: str

    @property
    def is_valid(self):
        return self.filename and self.download_url


@total_ordering
class Version:
    def __init__(self, val: Union[str, tuple[int, int, int]], unchecked: bool = False):
        if isinstance(val, str):
            tup = val.split(".", 3)
            self.__major = int(tup[0])
            self.__minor = int(tup[1])
            self.__patch = int(tup[2])
        else:
            self.__major = val[0]
            self.__minor = val[1]
            self.__patch = val[2]

        if not unchecked:
            if self < Version.min():
                raise ValueError(f"Version must be >= {Version.min()}")
            if self > Version.max():
                raise ValueError(f"Version must be <= {Version.max()}")

    @classmethod
    def from_int(cls, num: int) -> Version:
        divpatch = cls.max().__patch
        divminor = cls.max().__minor
        divmajor = cls.max().__major
        num, patch = (num // divpatch, num % divpatch)
        num, minor = (num // divminor, num % divminor)
        num, major = (num // divmajor, num % divmajor)
        if num != 0:
            raise ValueError("Overflowing number")
        return cls((major, minor, patch))

    @classmethod
    def mid(cls, a: Version, b: Version) -> Version:
        return cls.from_int((int(a) + int(b)) // 2)

    @classmethod
    def min(cls) -> Version:
        return cls("0.0.0", unchecked=True)

    @classmethod
    def max(cls) -> Version:
        return cls("10.20.20", unchecked=True)

    def __int__(self) -> int:
        m = 1
        v = self.__patch * m
        m *= self.max().__patch
        v += self.__minor * m
        m *= self.max().__minor
        v += self.__major * m
        return v

    def __str__(self):
        return f"{self.__major}.{self.__minor}.{self.__patch}"

    def __add__(self, other):
        return Version.from_int(int(self) + int(other))

    def __sub__(self, other):
        return Version.from_int(int(self) - int(other))

    def __mul__(self, other):
        return Version.from_int(int(self) * int(other))

    def __floordiv__(self, other):
        return Version.from_int(int(self) // int(other))

    def __eq__(self, other):
        return (
            self.__major == other.__major
            and self.__minor == other.__minor
            and self.__patch == other.__patch
        )

    def __lt__(self, other):
        return (
            self.__major < other.__major
            or self.__minor < other.__minor
            or self.__patch < other.__patch
        )

    def __hash__(self):
        return int(self)


class VersionTests(unittest.TestCase):
    def test_int(self):
        a = Version("2.5.7")
        b = Version.from_int(int(a))
        self.assertEqual(a, b)

    def test_floordiv(self):
        v = Version("2.4.6") // 2
        self.assertEqual(v, Version("1.2.3"))

    def test_add(self):
        a = Version("1.2.3")
        b = Version("2.3.4")
        v = a + b
        self.assertEqual(v, Version("3.5.7"))

    def test_mid(self):
        a = Version("2.2.3")
        b = Version("10.20.20")
        v = Version.mid(a, b)
        self.assertEqual(v, Version((6, 11, 11)))


def niceprint(type: str, *values: object):
    global console
    match type:
        case "OK":
            prefix = "[green]\\[  OK  ][/green]"
        case "INFO":
            prefix = "[white]\\[ INFO ][/white]"
        case "ERROR":
            prefix = "[red]\\[ ERRO ][/red]"
        case "WARN":
            prefix = "[yellow]\\[ WARN ][/yellow]"
        case _:
            raise ValueError(f"Unknown type {type}")
    console.print(prefix, *values)


def parse_fw_filename(s: str) -> tuple[str, str, Version, str]:
    match = re.fullmatch(r"(.*)(.)(\d+\.\d+\.\d+)(\..*)", s)
    name = match.group(1)
    sep = match.group(2)
    version_str = match.group(3)
    ext = match.group(4)
    return (name, sep, Version(version_str), ext)


def sanitize_fws(iter: Iterable[Firmware]) -> Iterable[Firmware]:
    return (fw for fw in sorted(iter, key=lambda x: x.filename) if fw.is_valid)


@cache
def http_request(method: str, url: str, retry: int | None = -1):
    backoff = 10
    max_backoff = 300
    last_exception: Exception | None = None
    while retry:
        reqtext = f"Request {method} {url}"
        try:
            response = httpx.request(
                method, url, headers=IMPERSONATE_HEADERS, timeout=120.0
            )
            response = httpx.get(url, headers=IMPERSONATE_HEADERS, timeout=120.0)
            response.raise_for_status()
            niceprint("OK", reqtext)
            return response.read()
        except TimeoutException as e:
            last_exception = e
            niceprint("ERROR", f"{reqtext}: Timeout")
        except HTTPStatusError as e:
            last_exception = e
            match (e.response.status_code, e.response.headers.get("server")):
                case (code, _) if code >= 500 and code <= 599:
                    pass
                case 429:
                    pass
                # Server responds with AkamaiGHost when rate limits or other problems are encountered.
                case 403, "AkamaiGHost":
                    pass
                case _:
                    raise e
            niceprint("ERROR", f"{reqtext}: HTTP Status Code {e.response.status_code}")
        except HTTPError as e:
            last_exception = e
            niceprint("ERROR", f"{reqtext}: {e}")
        if retry != -1:
            retry -= 1
        if retry:
            niceprint("INFO", f"{reqtext}: Retrying request in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
    raise last_exception


def http_head(url: str, retry: int | None = -1) -> bool:
    return http_request("HEAD", url, retry)


def http_get(url: str, retry: int | None = -1) -> bytes:
    return http_request("GET", url, retry)


def get_firmware_list_json(version: str) -> str:
    version_safe = quote(version)
    url = f"https://api.shimano.com/etube/firmware/{version_safe}"
    return http_get(url).decode()


def get_firmware_list(version: str) -> list[Firmware]:
    return list(
        sanitize_fws(
            cattr.structure(json.loads(get_firmware_list_json(version)), list[Firmware])
        )
    )


def get_firmware_list_bisect() -> list[Firmware]:
    ver_min = Version("2.2.3")
    ver_max = Version("9.9.19")
    with Progress(console=console) as progress:
        task = progress.add_task("Searching for firmware", total=int(ver_max - ver_min))

        def inner(low: Version, high: Version):
            mid = Version.from_int((int(low) + int(high)) // 2)
            final = low == mid or high == mid

            # Get all firmware using bisection
            a = get_firmware_list_json(str(mid))
            b = get_firmware_list_json(str(high))

            if a == b:
                progress.update(task, advance=int(high - mid))
                return {a, *([] if final else inner(low, mid))}
            else:
                dct = {a, b}
                if not final:
                    c = inner(low, mid)
                    d = inner(mid, high)
                    dct = dct.union(c).union(d)
                return dct

        json_fws_set = inner(ver_min, ver_max)
        fws = set()
        for json_fws in json_fws_set:
            data = json.loads(json_fws)
            fws = fws.union(cattr.structure(data, set[Firmware]))
        return list(sanitize_fws(fws))


def firmware_scrape() -> dict[str, list[Version]]:
    data = dict()
    with Progress(console=console, auto_refresh=False) as progress:
        urls = (
            "https://bike.shimano.com/products/apps/e-tube-project-cyclist.html",
            "https://bike.shimano.com/products/apps/e-tube-project-professional.html",
        )
        fetch_task = progress.add_task("Fetching firmware pages", total=2)
        scrape_tasks = [
            progress.add_task(f"Scraping page #{index + 1}")
            for index, _ in enumerate(urls)
        ]

        for index, url in enumerate(urls):
            html = http_get(url).decode()
            progress.update(fetch_task, advance=1)
            progress.refresh()
            soup = BeautifulSoup(html, features="html.parser")
            table = soup.select_one(".firmware-table")
            rows = table.select("tbody tr")

            for row in rows:
                model = row.select_one(".firmware-modelNo").text
                version = row.select_one(".firmware-version").text
                if "(" in model:
                    model = model.split("(", maxsplit=1)[1].replace(")", "").strip()
                data.setdefault(model, list()).append(version)
                progress.update(scrape_tasks[index], advance=1)
                progress.refresh()

    return data


def get_all_firmware() -> list[Firmware]:
    niceprint("INFO", "Retrieving firmware from API")
    fws = get_firmware_list_bisect()
    fws_dict: dict[str, list[Firmware]] = dict()
    for fw in fws:
        (name, *_) = parse_fw_filename(fw.filename)
        fws_dict.setdefault(name, []).append(fw)
    niceprint("INFO", "Scraping website")
    scraped = firmware_scrape()
    scraped_models_norm = {name: name.replace("-", "") for name in scraped.keys()}
    fw_name_models: dict[str, str] = dict()
    for name, fw in track(
        fws_dict.items(), description="Matching API <-> Scraped", console=console
    ):
        result = next(
            (
                (model, f"substr ({model})")
                for (model, model_norm) in scraped_models_norm.items()
                if model_norm in name
            ),
            None,
        ) or next(
            (
                (model, f"rev. substr ({model})")
                for (model, model_norm) in scraped_models_norm.items()
                if name in model_norm
            ),
            None,
        )
        (ok, (model, note)) = (result is not None, result if result else (None, None))

        if not ok:
            val = max(
                (
                    (
                        model,
                        difflib.SequenceMatcher(None, name, model_norm).ratio(),
                    )
                    for (model, model_norm) in scraped_models_norm.items()
                ),
                key=lambda x: x[1],
            )
            (ok, model, note) = (
                val[1] > 0.7,
                val[0],
                f"similar ({val[0]}, ratio: {val[1]})",
            )

        if ok:
            fw_name_models[name] = model
            niceprint("INFO", f"{name}: {note}")
        else:
            fw_name_models[name] = None
            niceprint("INFO", f"{name}: No match with scraped data.")

    fws_all_set: set[Firmware] = set()
    for name, model in fw_name_models.items():
        name_fws = fws_dict[name]
        for fw in name_fws:
            fws_all_set.add(fw)
        if model is not None:
            (basename, sep, version, ext) = parse_fw_filename(fw.filename)
            for version in scraped[model]:
                filename = f"{basename}{sep}{version}{ext}"
                fws_all_set.add(
                    Firmware(
                        download_url=f"https://api.shimano.com/etube/public/data/upload/published/{filename}",
                        filename=f"{filename}",
                        version=str(version),
                        type=fw.type,
                        filesize=None,
                        md5=None,
                    )
                )

    niceprint("INFO", "Verifying firmware URLs")
    fws_all: list[Firmware] = []
    for fw in track(
        sorted(fws_all_set, key=lambda x: x.filename),
        description="Verifying firmware URLs",
        console=console,
    ):
        try:
            http_head(fw.download_url)
            fws_all.append(fw)
        except HTTPStatusError as e:
            niceprint(
                "WARN",
                f"Ignoring firmware '{fw.filename}': HTTP Error {e.response.status_code}",
            )

    return fws_all
