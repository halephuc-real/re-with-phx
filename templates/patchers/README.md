# Patcher templates

Small, dependency-free starting points for static and runtime patching.

## PE patcher

```bash
python pe_patcher.py target.exe --rva 0x1234 --bytes "90 90 90 90" -o target.patched.exe
python pe_patcher.py target.exe --pattern "48 8B 05 ?? ?? ?? ??" --bytes "B8 01 00 00 00 C3"
```

Features:

- RVA to file-offset translation through the section table
- Optional expected-byte verification
- Pattern search with `??` wildcards
- Backup by writing to a separate output file
- SHA-256 of original and patched files

## ELF patcher

```bash
python elf_patcher.py target --offset 0x1234 --bytes "90 90"
python elf_patcher.py target --vaddr 0x401000 --bytes "B8 01 00 00 00 C3"
```

Features:

- File-offset or virtual-address patching
- Program-header based virtual-address mapping
- Optional expected-byte verification
- Pattern search with `??` wildcards
- SHA-256 of original and patched files

## Frida hook template

Use `frida_hook_template.js` as a starting point for runtime patches that avoid
touching the original file.

```bash
frida -f target.exe -l frida_hook_template.js --no-pause
```

Adjust the module name, export name, and the replacement return value before
running it.

## Rules

- Verify the target build before patching.
- Keep the original file and hashes.
- Prefer a runtime hook when static patching breaks integrity checks.
- Re-sign the artifact when the platform requires it.
- Test in a VM or disposable device.
