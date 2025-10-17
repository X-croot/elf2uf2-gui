# ELF2UF2 GUI Tool

ELF2UF2 is a JavaFX-based graphical application designed to convert ELF or BIN files into UF2, BIN, or Intel HEX formats. This tool is ideal for developers working with microcontrollers such as the RP2040 family (Raspberry Pi Pico, Adafruit Feather, etc.) who need to generate firmware images in multiple formats.



* All integers are little-endian.
* The payload is copied from the input image, and remaining bytes are padded to match the block size.
* `Family ID` is inserted at offset 0x1F8 only if a family ID is specified.
* `Magic End` is always written at offset 0x1FC.
* Block size defaults to 256 bytes for most RP2040 boards, adjustable via settings.
<img width="1086" height="802" alt="screenshot" src="https://github.com/user-attachments/assets/a5da43b4-39c2-4c79-a1f3-b6a9f892b023" />

## Build and Run from Source

You can also build and run ELF2UF2 from source directly:

**Clone the repository:**

```bash
git clone https://github.com/X-croot/elf2uf2-gui.git
cd elf2uf2-gui

```


**Run the application:**

```bash
mvn dependency:resolve
mvn javafx:run
```

> **Requirements:** Java 17 or higher, Maven installed.



## Usage

* Click `Select File` to load an ELF or BIN file.
* Choose the desired output format (UF2, BIN, or Intel HEX).
* Adjust optional settings such as base address, payload size, and hash type.
* Optionally, select a preset for supported RP2040 boards.
* Click `Convert` to generate the output file.
* Preview the hex/ASCII dump and metadata for verification.

