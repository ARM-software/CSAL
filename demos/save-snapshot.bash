#!/bin/bash
# save snapshot data into a dated tar file
sudo chown mleach:users *.ini
sudo chown mleach:users *.bin
tar -czf trc_snp_"$(date +%y%0m%0d_%0H%0M)".tgz *.ini *.bin
