#!/bin/bash

IMAGE_URL="https://download.freebsd.org/releases/ISO-IMAGES/14.2/FreeBSD-14.2-RELEASE-arm64-aarch64-bootonly.iso"
IMAGE_NAME="FreeBSD-14.2-RELEASE-arm64-aarch64-bootonly.iso"

# Check if the image file already exists
if [ -f "$IMAGE_NAME" ]; then
    echo "Image file '$IMAGE_NAME' already exists. No need to download."
else
    echo "Image file not found. Downloading..."
    
    if command -v curl &> /dev/null; then
        curl -o "$IMAGE_NAME" "$IMAGE_URL"
    else
        echo "curl is not installed. Please install one to proceed."
        exit 1
    fi
    
    echo "Download completed."
fi

./builddir/scorpi -s 0,hostbridge -o console=stdio -o bootrom=./firmware/u-boot.bin -s 1,virtio-net,slirp  -s 2,virtio-blk,$IMAGE_NAME,ro -m 2G -c 4 vm1
