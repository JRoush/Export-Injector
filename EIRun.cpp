/*
    Basic stand-alone environment for ExportInjector library
*/

#include "windows.h"
#include "ExportInjector.h"

int main(int argc, char* argv[])
{    
    Autoload(argc,argv);
    return EXIT_SUCCESS;
}