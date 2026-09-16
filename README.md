# cpu-vuln

C command-line program that runs some `inline assembly` to retrieve the `msr` from the CPU, listing hardware mitigations.
Then, it parses the Linux kernel's `sysfs` vulnerability directory and uses ANSI escape sequences to color-code the results.

### Compile:
```bash
make
```

### Clean up:
```bash
make clean
```
