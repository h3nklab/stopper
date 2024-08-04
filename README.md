This is a mini-filter driver project to add breakpoint in IRP process in windows for debugging purpose.
It adds the breakpoint through command line to any IRP events in windows driver.

To use:
1. Install the driver:
1.1. Open windows explorer and right click into stopper.inf
1.2. Choose Install

2. To get command help, just run stpcmd.exe

3. To add breakpoint use command ADD.
   i.e.: stpcmd ADD /mj 0 /act false