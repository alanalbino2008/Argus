"""Entry point of the packaged Argus desktop app (PyInstaller starts here)."""

import multiprocessing

from argus.desktop import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # Windows: packaged apps must call this before anything else
    main()
