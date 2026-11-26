#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run LLVM coverage analysis for libraries.

This script replays fuzzing campaigns with the llvm-cov instrumented driver
and writes per-hour coverage under database/<library>/latest/cov.
"""
from loguru import logger
from pathlib import Path
import subprocess
import tomllib
import click
from typing import Optional

from utils import get_aflpp, list_libraries, save_config_file


# Global configuration
DATABASE_PATH = Path(__file__).parent.parent.resolve()
DEFAULT_IDENTIFICATION = "promefuzz"

# TOML template for coverage configuration
COVERAGE_CONFIG_TEMPLATE = """[aflpp]
fuzzer_path = "{afl_path}"
timeout = "{timeout}"

[{lib_name}]
[{lib_name}.latest.{identification}]
fuzzer = "aflpp"
bin = "./{lib_name}/latest/out/fuzz_driver/aflpp_synthesized_driver"
bin_asan = "./{lib_name}/latest/out/fuzz_driver/aflpp_synthesized_driver"
bin_gcov = "./{lib_name}/latest/out/fuzz_driver/gcov_synthesized_driver"
bin_cov = "./{lib_name}/latest/out/fuzz_driver/cov_synthesized_driver"
build_gcov = "./{lib_name}/latest/build_gcov"
out_base_path = "./{lib_name}/latest/fuzz"
in_path = "./{lib_name}/in"
cmd = "@@"
"""


def run_coverage_analysis(
    lib_name: str,
    pool_size: int = 1,
    identification: str = DEFAULT_IDENTIFICATION,
) -> bool:
    """
    Run LLVM coverage analysis for a specific library.

    Args:
        lib_name: Name of the library to analyze
        pool_size: Parallel seed replay workers
        identification: Identification string for the campaign

    Returns:
        bool: True if coverage analysis completed successfully, False otherwise
    """
    try:
        if not _validate_library_structure(lib_name):
            return False

        config_path = _generate_coverage_config(lib_name, identification)
        if not config_path:
            return False

        return _execute_coverage_analysis(
            lib_name, config_path, pool_size, identification
        )

    except Exception as e:
        logger.error(f"Failed to run LLVM coverage analysis for {lib_name}: {e}")
        return False


def _validate_library_structure(lib_name: str) -> bool:
    """Validate that the library has the required structure for LLVM coverage."""
    path_library = DATABASE_PATH / lib_name
    latest_dir = path_library / "latest"
    driver_dir = latest_dir / "out" / "fuzz_driver"
    fuzz_dir = latest_dir / "fuzz"

    missing_paths = []

    if not latest_dir.exists():
        missing_paths.append(str(latest_dir))
    if not driver_dir.exists():
        missing_paths.append(str(driver_dir))
    if not fuzz_dir.exists():
        missing_paths.append(str(fuzz_dir))

    if missing_paths:
        logger.error(
            f"Missing required directories for {lib_name}: {', '.join(missing_paths)}"
        )
        return False

    cov_driver = driver_dir / "cov_synthesized_driver"
    if not cov_driver.exists():
        logger.error(f"LLVM coverage driver not found: {cov_driver}")
        return False

    logger.info(f"Library structure validated for LLVM coverage analysis: {lib_name}")
    return True


def _cov_driver_config_path(lib_name: str) -> str:
    return f"./{lib_name}/latest/out/fuzz_driver/cov_synthesized_driver"


def _generate_coverage_config(lib_name: str, identification: str) -> Optional[Path]:
    """Generate a fuzz.toml that points llvm-cov at the instrumented driver."""
    try:
        driver_dir = DATABASE_PATH / lib_name / "latest" / "out" / "fuzz_driver"
        config_path = driver_dir / "fuzz.toml"

        if config_path.exists():
            logger.info(f"Using existing fuzz config: {config_path}")
        else:
            aflpp_path = get_aflpp()
            config_content = COVERAGE_CONFIG_TEMPLATE.format(
                afl_path=aflpp_path / "afl-fuzz",
                lib_name=lib_name,
                timeout=24,
                identification=identification,
            )
            config_path.write_text(config_content)
            logger.info(f"Generated coverage config: {config_path}")

        if not _ensure_bin_cov(config_path, lib_name, identification):
            return None
        return config_path

    except Exception as e:
        logger.error(f"Failed to generate coverage config for {lib_name}: {e}")
        return None


def _ensure_bin_cov(config_path: Path, lib_name: str, identification: str) -> bool:
    """Make sure fuzz.toml names the llvm-cov driver as bin_cov."""
    data = tomllib.loads(config_path.read_text())
    try:
        section = data[lib_name]["latest"][identification]
    except KeyError:
        logger.error(
            f"{config_path} has no [{lib_name}.latest.{identification}] section"
        )
        return False

    expected = _cov_driver_config_path(lib_name)
    if section.get("bin_cov"):
        return True

    section["bin_cov"] = expected
    if not save_config_file(config_path, data):
        return False
    logger.info(f"Added bin_cov to {config_path}")
    return True


def _execute_coverage_analysis(
    lib_name: str, config_path: Path, pool_size: int, identification: str
) -> bool:
    """Execute LLVM coverage collection."""
    try:
        cov_script = DATABASE_PATH / "utils" / "cov.py"

        if not cov_script.exists():
            logger.error(f"LLVM coverage script not found: {cov_script}")
            return False

        cov_cmd = [
            str(cov_script),
            "-c",
            str(config_path),
            "-ps",
            str(pool_size),
            "-v",
            "latest",
            "-p",
            lib_name,
            "-fi",
            identification,
        ]

        logger.info(
            f"Starting LLVM coverage analysis for {lib_name} with command: {' '.join(cov_cmd)}"
        )
        subprocess.run(cov_cmd, cwd=DATABASE_PATH, check=True)
        logger.success(f"LLVM coverage analysis completed successfully for {lib_name}")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"LLVM coverage analysis failed for {lib_name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during LLVM coverage analysis for {lib_name}: {e}")
        return False


@click.command()
@click.argument("mode", type=click.Choice(["one", "all"]))
@click.argument("library_name", required=False)
@click.option(
    "--pool-size",
    "-ps",
    default=1,
    help="Parallel seed replay workers for llvm-cov",
)
@click.option(
    "--identification",
    "-i",
    default=DEFAULT_IDENTIFICATION,
    help="Campaign identification string",
)
def main(
    mode: str, library_name: Optional[str], pool_size: int, identification: str
) -> None:
    """
    Run LLVM coverage analysis for libraries.

    MODE: Choose 'one' to analyze a specific library or 'all' to analyze all libraries.
    LIBRARY_NAME: Required when MODE is 'one'. Specify which library to analyze.
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

        success = run_coverage_analysis(library_name, pool_size, identification)
        if not success:
            logger.error(f"Failed to run LLVM coverage analysis for {library_name}")
            exit(1)

    elif mode == "all":
        failed_libraries = []
        successful_libraries = []

        for lib in list_libraries:
            logger.info(f"Starting LLVM coverage analysis for {lib}")
            success = run_coverage_analysis(lib, pool_size, identification)

            if success:
                successful_libraries.append(lib)
            else:
                failed_libraries.append(lib)

        if successful_libraries:
            logger.success(
                f"Successfully completed LLVM coverage analysis for: {', '.join(successful_libraries)}"
            )
        if failed_libraries:
            logger.warning(
                f"Failed LLVM coverage analysis for: {', '.join(failed_libraries)}"
            )
            exit(1)
        else:
            logger.success("All LLVM coverage analyses completed successfully")


if __name__ == "__main__":
    main()
