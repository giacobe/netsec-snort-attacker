# netsec-snort-attacker

Root filesystem overlay for the staged intrusion generator in the PolyLab
three-stage Snort exercise.

The generator derives its source identities and stage values from the standard
PolyLinux email/date identity supplied on the kernel command line. The defender
selects stages by sending control messages to UDP port 9999.

This repository is payload input for `buildroot-builder2` script 03. Package it
against the `snort-attacker` baseline with:

```sh
scripts/03-package-payload.sh \
  --baseline artifacts/<snort-attacker-artifact> \
  --repo https://github.com/giacobe/netsec-snort-attacker \
  --ref main \
  --payload-subdir rootfs-overlay \
  --archive-dest / \
  --permissions-file permissions.txt \
  --output-prefix packaged-attacker \
  --output packaged \
  --force
```

`permissions.txt` records the required ownership and Unix modes. Verify the
payload bytes on Linux with:

```sh
sha256sum -c SHA256SUMS
```

This payload repository is deliberately independent of the script 02 Buildroot
baseline configuration.
