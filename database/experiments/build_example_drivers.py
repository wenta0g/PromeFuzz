#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compile example fuzz drivers for fuzzing experiments.

This script compiles fuzz drivers from the examples directory, including
drivers for AFL++, GCOV, and LLVM source-based coverage (llvm-cov).
"""
from loguru import logger
from pathlib import Path
import subprocess
import click
from typing import Optional

from utils import get_aflpp, list_libraries


# Global paths
DATABASE_PATH = Path(__file__).parent.parent.resolve()
EXAMPLES_DIR = Path(__file__).parent.parent.parent.resolve() / "examples"
AFLPP_PATH = get_aflpp()


def compile_library_examples(lib_name: str) -> bool:
    """
    Compile fuzz drivers for a specific library.

    Args:
        lib_name: Name of the library to compile examples for

    Returns:
        bool: True if compilation was successful, False otherwise
    """
    path_library = DATABASE_PATH / lib_name
    latest_path = path_library / "latest"

    if not latest_path.exists():
        logger.critical(
            f"Library build directory '{latest_path}' does not exist. Please build {lib_name} first"
        )
        return False

    lib_example_dir = EXAMPLES_DIR / lib_name
    if not lib_example_dir.exists():
        logger.critical(
            f"Examples directory '{lib_example_dir}' does not exist. Please add examples for {lib_name} first"
        )
        return False

    # Set up output directory for fuzz drivers
    fuzz_driver_dir = latest_path / "out" / "fuzz_driver"
    cov_driver = fuzz_driver_dir / "cov_synthesized_driver"
    cov_only = False
    if fuzz_driver_dir.exists() and cov_driver.exists():
        logger.warning(
            f"Fuzz driver directory '{fuzz_driver_dir}' already exists. Skipping compilation for {lib_name}"
        )
        return True
    if fuzz_driver_dir.exists():
        logger.info(
            f"Fuzz drivers for {lib_name} exist without an LLVM coverage binary. Compiling it"
        )
        cov_only = True

    try:
        fuzz_driver_dir.mkdir(parents=True, exist_ok=True)

        # Copy synthesized drivers
        synthesized_src = lib_example_dir / "synthesized"
        synthesized_dst = fuzz_driver_dir / "synthesized"
        if synthesized_src.exists() and not synthesized_dst.exists():
            subprocess.run(
                ["cp", "-r", str(synthesized_src), str(synthesized_dst)], check=True
            )
        elif not synthesized_src.exists():
            logger.warning(
                f"Synthesized directory '{synthesized_src}' not found for {lib_name}"
            )

        # Copy and modify build script
        build_script_src = lib_example_dir / "build_additional_synthesized_driver.sh"
        build_script_dst = fuzz_driver_dir / "build_additional_synthesized_driver.sh"

        if not build_script_src.exists():
            logger.error(f"Build script '{build_script_src}' not found for {lib_name}")
            return False

        # Copy and update build script paths. The LLVM coverage compile stays.
        _copy_and_update_build_script(
            build_script_src, build_script_dst, lib_name, latest_path
        )

        if cov_only:
            cov_cmd = _cov_compile_command(build_script_dst)
            subprocess.run(
                ["bash", "-c", cov_cmd], cwd=DATABASE_PATH.parent, check=True
            )
        else:
            subprocess.run(
                ["bash", str(build_script_dst)], cwd=DATABASE_PATH.parent, check=True
            )

        if not cov_driver.exists():
            logger.error(f"LLVM coverage driver was not produced: {cov_driver}")
            return False

        logger.success(f"Successfully compiled fuzz drivers for {lib_name}")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to compile fuzz drivers for {lib_name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while compiling {lib_name}: {e}")
        return False


def _copy_and_update_build_script(
    src_script: Path, dst_script: Path, lib_name: str, latest_path: Path
) -> None:
    """
    Copy build script and update paths to match current environment.

    Args:
        src_script: Source build script path
        dst_script: Destination build script path
        lib_name: Library name for path replacement
        latest_path: Current library build path
    """
    subprocess.run(["cp", str(src_script), str(dst_script)], check=True)

    # Update script content to use correct paths
    script_content = dst_script.read_text()
    script_content = script_content.replace(
        f"/promefuzz/database/{lib_name}/latest", str(latest_path)
    )
    if not script_content.endswith("\n"):
        script_content += "\n"

    if "# cov" not in script_content:
        raise RuntimeError(
            f"Build script '{src_script}' has no LLVM coverage section ('# cov')"
        )

    dst_script.write_text(script_content)


def _cov_compile_command(script_path: Path) -> str:
    """Return the LLVM coverage compile commands from a build script."""
    lines = script_path.read_text().splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "# cov")
    except StopIteration as exc:
        raise RuntimeError(
            f"Build script '{script_path}' has no LLVM coverage section ('# cov')"
        ) from exc

    cov_lines = [
        line
        for line in lines[start + 1 :]
        if line.strip() and not line.strip().startswith("#")
    ]
    if not cov_lines:
        raise RuntimeError(
            f"Build script '{script_path}' has an empty LLVM coverage section"
        )
    return "\n".join(cov_lines) + "\n"


@click.command()
@click.argument("mode", type=click.Choice(["one", "all"]))
@click.argument("library_name", required=False)
def main(mode: str, library_name: Optional[str]) -> None:
    """
    Compile fuzz drivers from examples for fuzzing experiments.

    MODE: Choose 'one' to compile an example fuzz driver from a specific library
          or 'all' to compile all example fuzz drivers.
    LIBRARY_NAME: Required when MODE is 'one'. Specify which library to compile fuzz driver.
    """
    if mode == "one":
        if not library_name:
            logger.critical("Please provide the library name when using 'one' mode")
            exit(1)
        if library_name not in list_libraries:
            logger.critical(
                f"'{library_name}' is not a valid library. "
                f"Available libraries: {', '.join(list_libraries)}"
            )
            exit(1)

        success = compile_library_examples(library_name)
        if not success:
            exit(1)

    elif mode == "all":
        failed_libraries = []
        for library in list_libraries:
            logger.info(f"Compiling examples for {library}...")
            success = compile_library_examples(library)
            if not success:
                failed_libraries.append(library)

        if failed_libraries:
            logger.warning(
                f"Failed to compile examples for: {', '.join(failed_libraries)}"
            )
            exit(1)
        else:
            logger.success("Successfully compiled examples for all libraries")


if __name__ == "__main__":
    main()
