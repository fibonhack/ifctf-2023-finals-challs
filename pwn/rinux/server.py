#!/usr/bin/env python3
from shutil import copyfile


def main():
    DELIMITER = "GABIBBOGABIBBOGABIBBOGABIBBO"
    print(f"Write here the hex of your rootfs.cpio. End with a line with only '{DELIMITER}'")
    content = ""
    while True:
        content += input("")
        if content.endswith(DELIMITER):
            break
    cpio_content = bytes.fromhex(content.split(DELIMITER)[0])

    if cpio_content[:6] != b"070701":
        print("This is not a cpio, where is my magic?")
        exit(-1)

    if len(cpio_content) > 2_000_000:
        print("File too big")
        exit(-1)

    with open("/tmp/rootfs.cpio", "wb") as outfile:
        outfile.write(cpio_content)
    copyfile("flag.txt", "/tmp/flag.txt")


if __name__ == "__main__":
    main()
