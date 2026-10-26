# Validation drivers

Run these commands from the repository root. The complete setup and mechanism description is in [`README.md`](../README.md).

```bash
python3 tests/fpm_eol_matrix.py --help
python3 tests/fpm_patch_marker_check.py --help
python3 tests/sapi_matrix.py --help
python3 tests/test_cve_109618_oom.py --help
```

The matrix driver creates its own temporary Docker resources, records a local JSON result and gdb transcript, and removes its containers when the run ends. Output paths are deliberately outside the tracked source tree.
