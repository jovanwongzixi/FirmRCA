#!/bin/bash

# Script to convert ARM ELF/SO files to binary format
# Usage: ./convert_to_bin.sh [directory]

# Set the directory to search (default to current directory)
TARGET_DIR="${1:-.}"

# Check if objcopy is available
if ! command -v arm-linux-gnueabihf-objcopy &> /dev/null; then
    echo "Error: arm-linux-gnueabihf-objcopy not found in PATH"
    echo "Please install the ARM toolchain (e.g., gcc-arm-linux-gnueabihf)"
    exit 1
fi

# Counter for statistics
success_count=0
fail_count=0

echo "Searching for ELF files in: $TARGET_DIR"
echo "----------------------------------------"

# Find all files and check if they are ELF files
while IFS= read -r -d '' file; do
    # Check if file is an ELF file
    if file "$file" | grep -q "ELF"; then
        output_file="${file}.bin"
        
        echo "Converting: $file"
        
        # Perform the conversion
        if arm-linux-gnueabihf-objcopy -O binary "$file" "$output_file" 2>/dev/null; then
            echo "  ✓ Created: $output_file"
            ((success_count++))
        else
            echo "  ✗ Failed to convert: $file"
            ((fail_count++))
        fi
    fi
done < <(find "$TARGET_DIR" -type f -print0)

echo "----------------------------------------"
echo "Conversion complete!"
echo "Successfully converted: $success_count files"
echo "Failed: $fail_count files"