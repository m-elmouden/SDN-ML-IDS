#!/bin/bash

# Fix the log file path
sed -i 's|self.log_file_path = \x27/app/network_logs.txt\x27|self.log_file_path = \x27network_logs.txt\x27|g' /mnt/hgfs/shared/seetupforLinux/ryu_app/enhanced_ids_kafka.py

# Fix the test topic issue
sed -i 's|test_topic = self.features_topic + \x27_test\x27|# Use the actual features topic instead of a test topic\n                test_topic = self.features_topic|g' /mnt/hgfs/shared/seetupforLinux/ryu_app/enhanced_ids_kafka.py

# Add unique consumer group ID
sed -i 's|group_id=\x27ryu-decision-consumer\x27,|group_id=\x27ryu-decision-consumer-\x27 + str(int(time.time())),  # Add timestamp to make unique|g' /mnt/hgfs/shared/seetupforLinux/ryu_app/enhanced_ids_kafka.py

echo "Fixed Ryu app configuration"
