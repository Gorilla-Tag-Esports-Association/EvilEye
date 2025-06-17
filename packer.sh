#!/bin/bash


DEST="./bin"


MINGW_BIN="/mingw64/bin"


SYS32="/c/Windows/System32"


REQUIRED_DLLS=(
    "libcrypto-3-x64.dll"
    "libssl-3-x64.dll"
    "libjsoncpp-26.dll"
    "libgcc_s_seh-1.dll"
    "libwinpthread-1.dll"
    "libstdc++-6.dll"
    "VCRUNTIME140.dll"
)


make
echo "make completed successfully."
echo "Copying required DLLs to: $DEST"

for dll in "${REQUIRED_DLLS[@]}"; do
    if [ -f "$MINGW_BIN/$dll" ]; then
        cp -v "$MINGW_BIN/$dll" "$DEST"
        continue
    fi


    if [ -f "$SYS32/$dll" ]; then
        cp -v "$SYS32/$dll" "$DEST"
        continue
    fi

    echo "❌ DLL not found: $dll"
done


echo "✅ Done."