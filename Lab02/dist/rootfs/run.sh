  #!/bin/sh

# Navigate to the modules directory
cd modules || { echo "Failed to enter modules directory"; exit 1; }

# Insert the kernel module
insmod cryptomod.ko || { echo "Failed to insert module"; exit 1; }

# Change permissions for test_crypto
chmod 777 test_crypto || { echo "Failed to change permissions"; exit 1; }

# Execute test_crypto with arguments
./test_crypto test 4 || { echo "Failed to execute test_crypto"; exit 1; }

