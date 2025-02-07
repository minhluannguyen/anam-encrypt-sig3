# Anamorphic Encryption Scheme

This repository contains an implementation of an anamorphic encryption scheme using Python. The scheme is based on public key cryptography and provides a way to embed hidden messages within encrypted data.
The script includes functionality to measure and plot the execution times of the normal mode and anamorphic mode processes. The execution times are measured for different input sizes and plotted using the `matplotlib` library. This helps in analyzing the performance of the anamorphic encryption scheme.

## Files

- `script.py`: The main script containing the implementation of the encryption and signature scheme.
- `readme.txt`: This file, providing an overview of the project.

## Dependencies

The following Python libraries are required to run the script:

- `random`
- `pycryptodome` (for AES encryption)
- `matplotlib` (for plotting execution times)

## References

- [Anamorphic Encryption, Revisited](https://eprint.iacr.org/2023/249.pdf)