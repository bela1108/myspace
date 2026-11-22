"""Generate cross-era sample Mach-O headers into .demo-headers/ (demo only)."""

import os

from macholib import mach_o
from macholib_tests.test_build_provenance import (
    CPU_TYPE_ARM64,
    CPU_TYPE_I386,
    CPU_TYPE_POWERPC,
    CPU_TYPE_X86_64,
    fat_macho,
    lc_build_version,
    lc_version_min_macosx,
    thin_macho,
)

OUT = ".demo-headers"

SAMPLES = {
    "2007-ppc-version-min": thin_macho(
        CPU_TYPE_POWERPC,
        [lc_version_min_macosx((10, 4, 0), (10, 4, 0), endian=">")],
        is_64=False,
        endian=">",
    ),
    "2012-i386-version-min": thin_macho(
        CPU_TYPE_I386, [lc_version_min_macosx((10, 6, 0), (10, 8, 0))], is_64=False
    ),
    "2023-arm64-build-version": thin_macho(
        CPU_TYPE_ARM64,
        [
            lc_build_version(
                mach_o.PLATFORM_MACOS,
                (13, 0, 0),
                (13, 1, 0),
                [(mach_o.TOOL_CLANG, (14, 0, 0)), (mach_o.TOOL_LD, (16, 2, 0))],
            )
        ],
    ),
    "fat-one-slice-has-tools": fat_macho(
        [
            (
                CPU_TYPE_X86_64,
                thin_macho(
                    CPU_TYPE_X86_64,
                    [
                        lc_build_version(
                            mach_o.PLATFORM_MACOS,
                            (12, 0, 0),
                            (12, 3, 0),
                            [(mach_o.TOOL_CLANG, (13, 1, 6))],
                        )
                    ],
                ),
            ),
            (
                CPU_TYPE_ARM64,
                thin_macho(
                    CPU_TYPE_ARM64, [lc_version_min_macosx((11, 0, 0), (12, 1, 0))]
                ),
            ),
        ]
    ),
    "fat-conflicting-clang": fat_macho(
        [
            (
                CPU_TYPE_X86_64,
                thin_macho(
                    CPU_TYPE_X86_64,
                    [
                        lc_build_version(
                            mach_o.PLATFORM_MACOS,
                            (12, 0, 0),
                            (12, 3, 0),
                            [(mach_o.TOOL_CLANG, (13, 1, 6))],
                        )
                    ],
                ),
            ),
            (
                CPU_TYPE_ARM64,
                thin_macho(
                    CPU_TYPE_ARM64,
                    [
                        lc_build_version(
                            mach_o.PLATFORM_MACOS,
                            (12, 0, 0),
                            (12, 3, 0),
                            [(mach_o.TOOL_CLANG, (14, 0, 3))],
                        )
                    ],
                ),
            ),
        ]
    ),
}


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    for name, data in sorted(SAMPLES.items()):
        with open(os.path.join(OUT, name), "wb") as fp:
            fp.write(data)
        print(os.path.join(OUT, name))


if __name__ == "__main__":
    main()
