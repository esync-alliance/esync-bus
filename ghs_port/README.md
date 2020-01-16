* Here are some notes when compiling and testing libxl4bus in INTEGRITY 
  - OpensSL: Used version OPenSSL_1_0_2K for easily porting to GreenHill. There are some minor modification like random generator which are automatically applied modified files during compilation process 
  - For remaining dependent modules, used same version and branch defined in .gitmodule of libxl4bus 
    Ther are some minor modifications for INTEGRITY. Those modification are applied automatically during compilation 
  
  - libxl4bus.a has been tested in INTEGRITY 
  - xl4bus-broker has been compiled but it has not been tested because there is no requirement for deploying broker in INTERITY