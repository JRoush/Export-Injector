#include <windows.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include "ExportInjector.h"
#include "ExportManager.h"

using namespace std;
#pragma warning (disable: 4996 4800) // unsafe cstring functions, forcing numeric value to bool

const unsigned int buffersz = 0x200;

// File searcher
typedef void (* FindFileCallback)(const char* filename);
int FindFile(const char* filename, FindFileCallback callback, bool recurse = false)
{
    string path(filename);
    string::size_type pathlen = path.rfind('\\') + 1;  // path length, including trailing seperator
    path.resize(pathlen);
    string subfile;
    WIN32_FIND_DATA file;
    int numfound = 0;
    // iteratre through matches and fire callback
    HANDLE findhndl = FindFirstFile(filename,&file);
    for (bool found = (findhndl != INVALID_HANDLE_VALUE); found; found = FindNextFile(findhndl,&file))
    {        
        subfile = path + file.cFileName;   // matched file
        callback(subfile.c_str());  
        numfound++;
    }        
    FindClose(findhndl);
    // iterate through directories and recurse
    if (recurse)
    {  
        
        HANDLE findhndl = FindFirstFile((path+"*").c_str(),&file);
        for (bool found = (findhndl != INVALID_HANDLE_VALUE); found; found = FindNextFile(findhndl,&file))
        {
            if ( file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && file.cFileName[0] != '.') 
            {
                subfile = path + file.cFileName;          // subdirectory
                subfile += "\\";                          // seperator
                subfile += filename + pathlen;            // filter
                numfound += FindFile(subfile.c_str(),callback,recurse);
            }
        }        
        FindClose(findhndl);
    }
    // return number of matches found
    return numfound;
}
// DEF loader
bool LoadEEDFile(const char* filename)
{
    std::ifstream ifs(filename);
    if (!ifs.is_open()) return false;
    std::stringstream oss;
    oss << ifs.rdbuf();
    std::string contents(oss.str());
    return ExportManager::ReadEED(contents);
}

// Implementation of external interface
int LoadExports(const char* filename, bool recurse)
{
    return FindFile(filename,(FindFileCallback)LoadEEDFile,recurse);
}   
bool WriteModuleDef(const char* filename, const char* module)
{
    ExportManager* eed = ExportManager::GetExportManager(module);
    if (!eed) return false;
    std::ofstream ofs(filename,std::ios_base::out);
    if (!ofs.is_open()) return false;
    eed->DebugDump();       // for debugging purposes
    eed->WriteDEF(ofs);
    return true;
}
void ModuleDebugDump(const char* module)
{
    ExportManager* g = ExportManager::GetExportManager(module,false);
    if (g) g->DebugDump();
    else cerr << "ExportInjector: Module '" << module << "' is does not have a managed export table" << endl;
}

// main entry point
void Autoload(int argc, char* argv[])
{    
    char basePath[buffersz] = {0};
    char filenameString[buffersz] = {0};
    char recurseString[buffersz] = {0};
    char defmodString[buffersz] = {0};
    char deftgtString[buffersz] = {0};

    // Parse command line
    cout << "ExportInjector: Parsing Command Line w/ " << argc << " args" << endl;
    for (int i = 1; i < argc; i++)
    {
        if (*argv[i] != '/') continue;  // argument is not a switch
        char* eq = strchr(argv[i],'=') + 1;
        if (eq < argv[i]) continue;     // switch has no value
        switch (*(long*)(argv[i]+1))
        {
            case 'eliF':    // Filename
                strcpy_s(filenameString,buffersz,eq);
                break;
            case 'uceR':    // Recurse
                strcpy_s(recurseString,buffersz,eq);
                break;
            case 'MFED':    // DEFModule
                strcpy_s(defmodString,buffersz,eq);
                break;
            case 'FFED':    // DEFFilename
                strcpy_s(deftgtString,buffersz,eq);
                break;
            default:
                cerr << "ExportInjector ERROR: Unrecognized switch '" << argv[i] << "'" << endl;
        }
    }

    // Parse local ini file
    GetCurrentDirectory(buffersz,basePath);
    cout << "ExportInjector: Parsing Local INI in '" << basePath << "'" << endl;    
    if (!filenameString[0]) GetPrivateProfileString("ExportInjector","Filename",NULL,filenameString,buffersz,"./ExportInjector.ini");
    if (!recurseString[0]) GetPrivateProfileString("ExportInjector","Recurse",NULL,recurseString,buffersz,"./ExportInjector.ini");
    if (!defmodString[0]) GetPrivateProfileString("ExportInjector","DEFmodule",NULL,defmodString,buffersz,"./ExportInjector.ini");
    if (!deftgtString[0]) GetPrivateProfileString("ExportInjector","DEFfilename",NULL,deftgtString,buffersz,"./ExportInjector.ini");

    // Parse base ini file    
    int pathlen = GetModuleFileName(GetModuleHandle("ExportInjector.dll"),basePath,buffersz);
    if (pathlen == 0) cerr << "ExportInjector ERROR: Could not determine path to base ini file" << endl;
    else if (pathlen == buffersz) cerr << "ExportInjector ERROR: Path to base ini file too large for buffer size " << buffersz << endl;
    else
    {
        strcpy((char*)(basePath + pathlen - 3),"ini");      // replace '.exe' with '.ini' 
        cout << "ExportInjector: Parsing Base INI : '" << basePath << "'" << endl;
        if (!filenameString[0]) {GetPrivateProfileString("ExportInjector","Filename",NULL,filenameString,buffersz,basePath);}
        if (!recurseString[0]) GetPrivateProfileString("ExportInjector","Recurse",NULL,recurseString,buffersz,basePath);
        if (!defmodString[0]) GetPrivateProfileString("ExportInjector","DEFmodule",NULL,defmodString,buffersz,basePath);
        if (!deftgtString[0]) GetPrivateProfileString("ExportInjector","DEFfilename",NULL,deftgtString,buffersz,basePath);
    }

    // load input files, tokenize on commas & strip quotes
    char* tgtctx = NULL;
    char* recctx = NULL;
    char* tgt = strtok_s(filenameString,",\"",&tgtctx);
    char* rec = strtok_s(recurseString,",\"",&recctx);
    while (tgt)
    {
        // determine filter string and recursion switch
        bool recurse = (rec) ? atoi(rec) != 0 : false;
        cout << "ExportInjector Filename '" << tgt << "' w/ recursion = " << recurse << endl;
        // load eed files
        LoadExports(tgt,recurse);
        // get next Filename
        tgt = strtok_s(NULL,",\"",&tgtctx);
        if (rec) rec = strtok_s(NULL,",\"",&recctx);
    }

    // dump DEF output, tokenize on commas & strip quotes
    char* modctx = NULL;
    char* defctx = NULL;
    char* mod = strtok_s(defmodString,",\"",&modctx);
    char* def = strtok_s(deftgtString,",\"",&defctx);
    while (mod)
    {
        // determine output file
        char* out = (def) ? def : "OBFE_defaultoutput.def";
        cout << "ExportInjector DEFout module '" << mod << "' to '" << out << "'" << endl;
        // dump def for module
        WriteModuleDef(out,mod);
        // get next output Filename
        mod = strtok_s(NULL,",\"",&modctx);
        if (def) def = strtok_s(NULL,",\"",&defctx);
    }

}

// entry point when loaded
BOOL WINAPI DllMain(__in  HINSTANCE hinstDLL, __in  DWORD fdwReason, __in  LPVOID lpvReserved)
{
    // temp stream, out file for redirecting output
    

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        cout << "ExportInjector: Attached to process at base " << std::hex << hinstDLL << endl; 
        if (!GetModuleHandle("ExportInjector.exe")) Autoload(); // autoload unless stand-alone driver detected

        /*
        // redirect std output streams
        std::streambuf *psbuf, *backup;
        std::ofstream filestr;
        filestr.open("ExportInjector.cout.log");
        backup = std::cout.rdbuf();                     // back up cout's streambuf
        psbuf = filestr.rdbuf();                        // get file's streambuf
        std::cout.rdbuf(psbuf);                         // redirect cout to streambuf
        freopen("ExportInjector.stdout.log","a",stdout);// redirect stdout to file
        */            
        
        /*
        // restore std output streams
        std::cout.rdbuf(backup);                        // restore cout's original streambuf
        filestr.close();
        fclose(stdout);                                 // restore original stdout
        */
        break;

    case DLL_PROCESS_DETACH:
        cout << "ExportInjector: Detached from process" << endl;
        break;

    default:
        cout << "ExportInjector: DLLMain call w/ Reason " << std::hex << fdwReason << endl;    
        break;
    }

    return true;
}


