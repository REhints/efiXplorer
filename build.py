#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020-2026 Binarly

import pathlib
import subprocess

import click

ROOT_DIR = pathlib.Path(__file__).resolve().parent


def cmake_build(source_dir: pathlib.Path, idasdk: str, hexrays_sdk: str | None = None):
    build_dir = pathlib.Path(source_dir) / "build"
    build_dir.mkdir(exist_ok=True)

    command = ["cmake", str(source_dir), f"-DIdaSdk_ROOT_DIR={idasdk}"]
    if hexrays_sdk is not None:
        click.secho("HexRays analysis is enabled", fg="green")
        command.append(f"-DHexRaysSdk_ROOT_DIR={hexrays_sdk}")
    else:
        click.secho("HexRays analysis is disabled", fg="yellow")

    subprocess.run(command, cwd=build_dir, check=True)
    subprocess.run(
        ["cmake", "--build", ".", "--config", "Release", "--parallel"],
        cwd=build_dir,
        check=True,
    )


def resolve_hexrays_sdk(idasdk: str, hexrays_sdk: str | None, no_hexrays: bool) -> str | None:
    if no_hexrays:
        return None
    return hexrays_sdk if hexrays_sdk else idasdk


def hexrays_options(f):
    f = click.option(
        "--hexrays_sdk",
        "hexrays_sdk",
        type=str,
        default=None,
        help="path to hexrays_sdk directory (default: IDASDK)",
    )(f)
    f = click.option(
        "--no-hexrays",
        "no_hexrays",
        is_flag=True,
        default=False,
        help="disable HexRays analysis",
    )(f)
    return f


@click.group()
def cli():
    pass


@cli.command()
@hexrays_options
@click.argument("idasdk")
def build_plugin(idasdk: str, hexrays_sdk: str, no_hexrays: bool):
    """Build plugin"""

    hrs = resolve_hexrays_sdk(idasdk, hexrays_sdk, no_hexrays)
    cmake_build(ROOT_DIR / "plugin", idasdk, hexrays_sdk=hrs)


@cli.command()
@click.argument("idasdk")
def build_loader(idasdk: str):
    """Build loader"""

    cmake_build(ROOT_DIR / "loader", idasdk)


@cli.command()
@hexrays_options
@click.argument("idasdk")
def build_all(idasdk: str, hexrays_sdk: str, no_hexrays: bool):
    """Build plugin and loader"""

    hrs = resolve_hexrays_sdk(idasdk, hexrays_sdk, no_hexrays)
    cmake_build(ROOT_DIR, idasdk, hexrays_sdk=hrs)


if __name__ == "__main__":
    cli()
