#include <INTEGRITY.h>
#include <unistd.h>
#include "broker_integrate.h"

extern void xl4_tablefd_preinit();

extern  int broker_main(int argc, char ** argv);
int main(int argc, char **argv)
{
    SignedValue sem_val = 0;

    WaitForFileSystemInitialization();
    getopt_init(argv[0]);

    xl4_tablefd_preinit();

    /*
    * This polling manner allows multiple tasks to detect the broker is in
    * ready status at the same time.
    */
    while(true){
        GetSemaphoreValue(BROKER_LINK_SYSTEM_TIME_READY_SHARED_SEM, &sem_val);
        if(sem_val > 0){
            printf(LOG_PREFIX"SYSTEM Time Updated\n");
            break;
        }else{
            usleep(500);
        }
    }

    return broker_main(argc, argv);
}
