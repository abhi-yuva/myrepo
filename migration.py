"""
Example:
    python migration.py tropos <other arguments>
    python migration.py onecloud <other arguments>
"""
import os
import sys
cluster_name = sys.argv[1]
check_args = " ".join(sys.argv[2:])
print('name', cluster_name)
if cluster_name.lower() == "tropos":
    os.system(f"python tropos.py {check_args}")
elif cluster_name.lower() == "onecloud":
    os.system(f"python onecloud.py {check_args}")
