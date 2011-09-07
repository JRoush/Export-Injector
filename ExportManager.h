/*
    ExportManager
    Moves Export Directory structure from PE header to heap, and provides an interface for managing the functions in the export table.
    Works only for modules loaded by the current process.
*/
#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <ostream>
#include <map>

class ExportManager
{
private:
    friend class ExportManagerMap;
    // Relative Virtual Address, a VA relative to module base
    typedef unsigned long               RVA;
    typedef std::vector<RVA>            RVAArrayT;
    typedef std::vector<unsigned short> OrdArrayT;
    // members   
    IMAGE_EXPORT_DIRECTORY  exportDir;              //
        //  DWORD           Characteristics;        // Flags
        //  DWORD           TimeDateStamp;          // Seconds since 1979
        //  WORD            MajorVersion;           // Version of directory structure?
        //  WORD            MinorVersion;           //
        //  DWORD           Name;                   // RVA to module name
        //  DWORD           Base;                   // Base for ordinal values
        //  DWORD           NumberOfFunctions;      // size of pFuncArray
        //  DWORD           NumberOfNames;          // size of pNameArray, ordinalArray
        //  DWORD           AddressOfFunctions;     // RVA to pFuncArray[0]
        //  DWORD           AddressOfNames;         // RVA to pNameArray[0]
        //  DWORD           AddressOfNameOrdinals;  // RVA to ordinalArray[0]
    unsigned long           moduleBase;             // cached module handle
    const char*             moduleName;             // cached module name
    IMAGE_DATA_DIRECTORY*   exportData;             // cached pointer to entry in PE header Directory Data array
    RVAArrayT               pFuncArray;             // array of RVA's to exported functions
    RVAArrayT               pNameArray;             // array of RVA's to names of exported functions
    OrdArrayT               ordinalArray;           // array of function ordinals (indep. of Base field)
    // RVA methods
    inline RVA              VAtoRVA(const void* va) const;  // convert an RVA into a useable pointer
    inline void*            RVAtoVA(RVA rva) const;         // convert a pointer into an RVA
    // match parsing methods
    // constructor, destructor
    ExportManager(const char* module);              // constructor, binds to Export Directory of specified module in current process
    ~ExportManager();                               // destructor, unbinds from export directory
public:
    // Add a function to the export table at specified ordinal (or anywhere if ordinal is -1).  Table may contain multiple entries for same 
    // function this is called multiple times with different explicit ordinals.  Names referring to the function are updated as necessary.
    // Returns final ordinal of function, or -1 if function pointer is null or ordinal is invalid (and not -1)
    long ExportFunc(FARPROC pFunc, long ordinal = -1); 
    // Add a name alias for the specified function ordinal.  If name is already present, it's current ordinal will be overwritten.
    // Returns false if name pointer, name, or ordinal are invalid.
    void ExportName(const char* name, long ordinal);  
    // Serializeation - parse from / write to 'Extended Export Definition' format (*.eed)
    static bool ReadEED(std::string& input);
    void WriteDEF(std::ostream& output);
    // Quickly retrieve the module handle to which this export table is bound
    HMODULE GetModule() const;                                        
    // Returns export manager for loaded module.  If create is true and no manager exists for specified (valid) module, one is created.
    static ExportManager*   GetExportManager(const char* module, bool create = false);
    // Debugging - for internal use   
    void DebugDump() const;
};  