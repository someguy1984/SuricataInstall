INSPECT drive - read-only Windows inspection

1. Double-click RUN-INSPECTION.cmd and accept the admin prompt (about 2-5 minutes).
   RUN-FULL-INSPECTION.cmd also runs chkdsk /scan, sfc /verifyonly and DISM /ScanHealth (20-40 minutes).
2. Wait for "Finished: N FAIL, N WARN".
3. On Linux: sudo ./inspect.sh collect

Results go to reports\<COMPUTER>-<time>\ on this drive. summary.txt is the overview.
Nothing on C: is changed and nothing is sent anywhere.
