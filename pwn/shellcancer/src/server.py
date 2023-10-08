#!/usr/bin/env python3
from os import urandom, makedirs, remove
from random import choice, randint
from pathlib import Path
from shutil import copyfile


FLAGFNAME = "flag.txt"


def main():
    curpath = Path(__file__).parent
    levels = randint(20, 30)
    for level in range(levels):
        dircount = randint(10, 20)
        directories = [urandom(4).hex() for _ in range(dircount)]
        for direc in directories:
            makedirs(curpath / direc)
        curpath = curpath / choice(directories)
    copyfile(FLAGFNAME, str(curpath / FLAGFNAME))
    remove(FLAGFNAME)


if __name__ == '__main__':
    main()
