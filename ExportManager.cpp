#include "ExportManager.h"
#include <ctime>
#include <iostream>
#include <algorithm>
#include <regex>
#include <cstdlib>
#include <sstream>

#include "EEDGrammarParser.h"
#include "EEDGrammarLexer.h"

using namespace std;
using namespace std::tr1;

#pragma warning (disable: 4244 4018)

// private methods
inline ExportManager::RVA ExportManager::VAtoRVA(const void* va) const
{
    if (va == NULL) return NULL;
    return (unsigned long)va - moduleBase;
}
inline void* ExportManager::RVAtoVA(ExportManager::RVA rva) const
{
    // TODO - consider switch to ImageRvaToVa() in dbghelp.dll 
    if (rva == NULL) return NULL;
    return (void*)(rva + moduleBase);
}
// constructor, destructor
ExportManager::ExportManager(const char* module)
{
    // cache module name
    int namesz = strlen(module) + 1;
    moduleName = new char[namesz];
    strcpy_s((char*)moduleName,namesz,module);    

    // initialize Export directory structure info
    exportDir.Characteristics       = 0x00000000;                   // No Flags
    exportDir.TimeDateStamp         = (unsigned long)time(NULL);    // Current time as timestamp
    exportDir.MajorVersion          = 0x0000;                       // Version info is cleared
    exportDir.MinorVersion          = 0x0000;
    exportDir.Name                  = VAtoRVA(moduleName);          // Pointer to cached name
    exportDir.Base                  = 0x1;  // Default base ordinal value
    exportDir.AddressOfFunctions    = 0x0;  // null array RVAs
    exportDir.AddressOfNames        = 0x0;
    exportDir.AddressOfNameOrdinals = 0x0;
    exportDir.NumberOfFunctions     = 0x0;  // zero out array sizes
    exportDir.NumberOfNames         = 0x0;

    // initialize arrays
    pFuncArray.clear();
    pNameArray.clear();
    ordinalArray.clear();

    // fetch module base
    moduleBase = (unsigned long)GetModuleHandle(module);
    if (!moduleBase) 
    {
        // module is not currently loaded, manager object is 'abstract'
        exportData = NULL;
        printf("ExportManager ctor: Module '%s' not currently loaded\n", moduleName); 
        return;
    }
    else printf("ExportManager ctor: Base address of loaded module '%s' = <%08X>\n", moduleName, moduleBase); 

    // traverse PE header to fetch Export Directory Data
    // TODO - consider using ImageNtHeader() from dbghelp.dll
    // ImageDirectoryEntryToDataEx() from dbghelp.dll might also be useful, but not sufficient
    IMAGE_DOS_HEADER*       dosHeader   = (IMAGE_DOS_HEADER*)moduleBase;   
    IMAGE_NT_HEADERS*       peHeader    = (IMAGE_NT_HEADERS*)RVAtoVA(dosHeader->e_lfanew);          
    printf("ExportManager ctor: Extracted PE header at <%08X>\n",peHeader);
    exportData  = &peHeader->OptionalHeader.DataDirectory[0];  // export directory has index 0
    printf("ExportManager ctor: Extracted Export Directory Data at <%08X>\n",exportData);
    
    // copy existing export table
    IMAGE_EXPORT_DIRECTORY* oldExportDir = (IMAGE_EXPORT_DIRECTORY*)RVAtoVA(exportData->VirtualAddress);
    if (oldExportDir)
    {
        // copy functions, init ordinals status
        RVA* pOldFuncArray = (RVA*)RVAtoVA(oldExportDir->AddressOfFunctions);
        pFuncArray.resize(oldExportDir->NumberOfFunctions);  
        exportDir.Base = oldExportDir->Base;           // Copy base ordinal value
        for (unsigned int i = 0; i < oldExportDir->NumberOfFunctions; i++) 
        { 
            pFuncArray[i] = pOldFuncArray[i]; 
            printf("ExportManager ExportFunc: #%04X, ordinal %04X @ (<%08X>,<%08X>)\n", i, exportDir.Base + i, pFuncArray[i], RVAtoVA(pFuncArray[i]));
        }
        
        exportDir.AddressOfFunctions = VAtoRVA(&pFuncArray[0]);     // Point to new array RVA
        exportDir.NumberOfFunctions = pFuncArray.size();            // Array size   
        // copy names & name ordinal refs
        RVA* pOldNameArray = (RVA*)RVAtoVA(oldExportDir->AddressOfNames);
        unsigned short* pOldOrdinalArray = (unsigned short*)RVAtoVA(oldExportDir->AddressOfNameOrdinals);
        pNameArray.resize(oldExportDir->NumberOfNames); 
        ordinalArray.resize(oldExportDir->NumberOfNames);
        for (unsigned int i = 0; i < oldExportDir->NumberOfNames; i++) 
        {
            pNameArray[i] = pOldNameArray[i];
            ordinalArray[i] = pOldOrdinalArray[i];
            printf("ExportManager ExportName: #%04X, ordinal %04X @ (<%08X>,<%08X>) '%s'\n", 
                i, ordinalArray[i]+exportDir.Base, pNameArray[i], RVAtoVA(pNameArray[i]), RVAtoVA(pNameArray[i]));  
        }
        exportDir.AddressOfNames = VAtoRVA(&pNameArray[0]);         // Point to new array RVAs
        exportDir.AddressOfNameOrdinals = VAtoRVA(&ordinalArray[0]);
        exportDir.NumberOfNames = pNameArray.size();                // Array size
    }
   
    // attach to module directory table
    unsigned long oldProtect;
    VirtualProtect(exportData, sizeof(*exportData), PAGE_EXECUTE_READWRITE, &oldProtect);
    exportData->VirtualAddress = VAtoRVA(&exportDir);
    exportData->Size = sizeof(*this);
    VirtualProtect(exportData, sizeof(*exportData), oldProtect, &oldProtect);        
    printf("ExportManager ctor: Set Export Directory Data (Dir RVA <%08X>, Dir Size %04X)\n",exportData->VirtualAddress, exportData->Size);
}
ExportManager::~ExportManager()
{   
    // free memory allocated for cached module name
    if (moduleName) delete [] moduleName;

    // free memory allocated for function names
    for (RVAArrayT::iterator itName = pNameArray.begin(); itName != pNameArray.end(); itName++)
    {
        if (*itName) delete RVAtoVA(*itName);
    }

    if (exportData)
    {
        // detach from module directory table
        unsigned long oldProtect;
        VirtualProtect(exportData, sizeof(*exportData), PAGE_EXECUTE_READWRITE, &oldProtect);
        exportData->VirtualAddress = NULL;
        exportData->Size = 0;
        VirtualProtect(exportData, sizeof(*exportData), oldProtect, &oldProtect);       
        printf("ExportManager Destructor: Set Export Directory Data (Dir RVA <%08X>, Dir Size %04X)\n",exportData->VirtualAddress, exportData->Size); 
    }
}
// Function, Name management
long ExportManager::ExportFunc(FARPROC pFunc, long ordinal /*= -1*/)
{    
    const RVA DUMMYRVA = -1;
    RVA rvaFunc = VAtoRVA(pFunc); 
    if (!rvaFunc) rvaFunc = DUMMYRVA; // bad function pointer, use a dummy rva
    long idxFunc = (ordinal < 0) ? pFuncArray.size() : ordinal - exportDir.Base;    // get offset in function array
    if (idxFunc < 0) return -1; // bad specified ordinal

    if (ordinal < 0)
    {   
        // ordinal unspecified
        RVAArrayT::iterator itFunc = std::find(pFuncArray.begin(),pFuncArray.end(),rvaFunc);        // search for target rva
        if (itFunc == pFuncArray.end()) itFunc = std::find(pFuncArray.begin(),pFuncArray.end(),0);  // search for empty slot
        if (itFunc == pFuncArray.end()) pFuncArray.push_back(VAtoRVA(pFunc));                       // append to end of array
        else idxFunc = itFunc - pFuncArray.begin();                                                 // valid index found
    }
    else if (pFuncArray.size() <= idxFunc)
    {
        // specified ordinal is beyond current array bounds, allocate dummy placeholders
        pFuncArray.resize(idxFunc + 1, 0);
    }    
    else if (pFuncArray[idxFunc] == rvaFunc || pFuncArray[idxFunc] == 0)
    {
        // function already at specified ordinal, or slot contains only a placeholder
    }
    else
    {
        // move current contents of slot
        RVA rvaCurrent = pFuncArray[idxFunc];
        long idxCurrent = 0;
        // find an empty to place old contents 
        RVAArrayT::iterator itFunc = std::find(pFuncArray.begin(),pFuncArray.end(),0);
        if (itFunc == pFuncArray.end())
        {
            // move old contents to end of array
            idxCurrent = pFuncArray.size();
            pFuncArray.push_back(rvaCurrent);            
        }
        else
        {
            // replace empty slot with old contents
            idxCurrent = itFunc - pFuncArray.begin();
            pFuncArray[idxCurrent] = rvaCurrent;
        }
        // update name refs to old contents
        for(OrdArrayT::iterator itOrd = std::find(ordinalArray.begin(),ordinalArray.end(),idxFunc); 
            itOrd != ordinalArray.end(); 
            itOrd = std::find(itOrd,ordinalArray.end(),idxFunc))
        {
            *itOrd = idxCurrent;
        }         
    }
    printf("ExportManager ExportFunc: #%04X, ordinal %04X @ (<%08X>,<%08X>)\n", idxFunc, exportDir.Base + idxFunc, rvaFunc, pFunc);
    pFuncArray[idxFunc] = rvaFunc;
    if (rvaFunc == DUMMYRVA) printf("ExportManager ExportFunc: WARNING: Added export entry for invalid function rva\n");
    // update array RVA and size in directory in case storage moved internally
    exportDir.AddressOfFunctions = VAtoRVA(&pFuncArray[0]);
    exportDir.NumberOfFunctions = pFuncArray.size();     
    // return 'useable' ordinal of added function
    return idxFunc + exportDir.Base;
}
void ExportManager::ExportName(const char* name, long ordinal)
{
    // Set name as alias for function ordinal
    // Mainatins invariant that name list is sorted in ascending order

    long idxFunc = ordinal - exportDir.Base;    // get offset in function array
    if (!name || *name == 0 || idxFunc < 0) {cout << "bad inputs to ExportName()\n";return;} // invalid name, empty name, or invalid ordinal

    int cmp = -1;
    RVAArrayT::iterator itName = pNameArray.begin();
    OrdArrayT::iterator itOrdinal = ordinalArray.begin();
    // find location for name in sorted array
    for(; itName != pNameArray.end(); itName++, itOrdinal++)
    {
        const char* n = (const char*)RVAtoVA(*itName);
        if (n) cmp = strcmp(n,name);
        if (cmp >= 0) break;
    }
    // update name/ordinal
    if (cmp == 0)
    {
        // name found already in array, update ordinal value to function index
        ordinalArray[itName - pNameArray.begin()] = idxFunc;
    }
    else
    {
        // create copy of name on heap
        int namesz = strlen(name) + 1;
        char* newname = new char[namesz]; 
        strcpy_s(newname,namesz,name);
        // insert name RVA & index to arrays
        itName = pNameArray.insert(itName,VAtoRVA(newname));
        ordinalArray.insert(itOrdinal,idxFunc);   
        // update array RVA and size in directory in case storage moved internally
        exportDir.AddressOfNames = VAtoRVA(&pNameArray[0]);
        exportDir.AddressOfNameOrdinals = VAtoRVA(&ordinalArray[0]);
        exportDir.NumberOfNames = pNameArray.size();
    }
    printf("ExportManager ExportName: #%04X, ordinal %04X @ (<%08X>,<%08X>) '%s'\n", itName - pNameArray.begin(), ordinal, *itName, RVAtoVA(*itName), name);  
}
// Get Module Handle
HMODULE ExportManager::GetModule() const
{
    return (HMODULE)moduleBase;
}
// Fetch/Create manager
class ExportManagerMap : public std::map<std::string, ExportManager*>
{
public:
    ~ExportManagerMap() 
    {
        // delete dynamically allocated manager objects
        printf("ExportManagerMap: destruct\n");
        for (ExportManagerMap::iterator it = begin(); it != end(); it++) { if (it->second) delete it->second; }
    }
};
ExportManagerMap exportManagerMap;
ExportManager* ExportManager::GetExportManager(const char* module, bool create /*= false*/)
{
    std::string key(module);
    ExportManagerMap::iterator it = exportManagerMap.find(key);
    if (it != exportManagerMap.end()) return it->second;    // return existing manager
    else
    {
        // create a new manager & bind to module
        ExportManager* man = new ExportManager(module);
        exportManagerMap.insert(std::pair<std::string, ExportManager*>(key,man));
        return man;
    }
}
// Serializeation
bool ExportManager::ReadEED(std::string& input)
{
    // construct input stream
    pANTLR3_INPUT_STREAM sinput = antlr3NewAsciiStringInPlaceStream ( (pANTLR3_UINT8)input.c_str(), (ANTLR3_UINT32)input.size(), NULL);
    // construct Lexer
    pEEDGrammarLexer lxr = EEDGrammarLexerNew(sinput);      
    // construct Token stream
    pANTLR3_COMMON_TOKEN_STREAM tstream = antlr3CommonTokenStreamSourceNew(ANTLR3_SIZE_HINT, TOKENSOURCE(lxr));
    // construct Parser
    pEEDGrammarParser psr = EEDGrammarParserNew(tstream);  
    // run parser from topmost rule
    psr->file(psr);
    bool result = true;
    if (psr->pParser->rec->state->errorCount > 0)
    {
        cerr << "EED Parser returned " << psr->pParser->rec->state->errorCount << " errors, processing aborted\n";
        result = false;
    }
    else
    {
        cout << "EED Parser completed successfully\n";
    }
    // deallocate memory (ANTLR generated code is strict C, uses malloc)
    psr     ->free  (psr);      psr     = NULL;
    tstream ->free  (tstream);  tstream = NULL;
    lxr     ->free  (lxr);      lxr     = NULL;
    sinput  ->close (sinput);   sinput  = NULL;
    // done
    return result;
}
void ExportManager::WriteDEF(std::ostream& output)
{   
    // Module name
    output << "NAME \"" << moduleName << "\"" << std::endl;

    // Exports statement
    output << "EXPORTS" << std::endl;

    // Exported functions w/ primary aliases
    std::vector<bool> nameused(pNameArray.size(),false);
    std::vector<const char*> primaryAlias(pFuncArray.size(),NULL);
    int unnamedCounter = 0;
    for (unsigned int i = 0; i < pFuncArray.size(); i++)
    {
        if (!pFuncArray[i]) continue;   // Empty slot
        // find first alias to function in names list
        std::vector<unsigned short>::const_iterator itName = std::find(ordinalArray.begin(),ordinalArray.end(),i);
        if (itName == ordinalArray.end())
        {
            // no alias found, use a dummy name
            output << "__UNNAMED_FUNCTION_" << unnamedCounter << " = #" << std::hex << std::uppercase << pFuncArray[i] << std::dec 
                << " @ " << i + exportDir.Base << " NONAME" << std::endl;
        }
        else
        {
            // function alias found
            unsigned int idxName = itName - ordinalArray.begin();
            primaryAlias[i] = (const char*)RVAtoVA(pNameArray[idxName]);
            output << primaryAlias[i] << " = #" << std::hex << std::uppercase << pFuncArray[i] << std::dec << std::endl;
            nameused[idxName] = true;            
        }
    }

    // export secondary aliases
    for (unsigned int i = 0; i < pNameArray.size(); i++)
    {
        if (nameused[i]) continue;  // symbol already exported as primary alias
        output << (const char*)RVAtoVA(pNameArray[i]) << " = " << primaryAlias[ordinalArray[i]] << std::endl;
    }
}
// Debugging
void ExportManager::DebugDump() const
{
    printf("ExportManager Attached to module '%s' @ <%08X> contains %i functions w/ %i names\n",moduleName,moduleBase,pFuncArray.size(),pNameArray.size());
    // enumerate function list
    printf("Function List:\n");
    for (unsigned int i = 0; i < pFuncArray.size(); i++) 
    {
        FARPROC proc = (FARPROC)RVAtoVA(pFuncArray[i]);
        std::vector<unsigned short>::const_iterator it = std::find(ordinalArray.begin(),ordinalArray.end(),i);
        if (it == ordinalArray.end())
        {
            printf("  Func #%04i @ <%08X,%08X>\n",i,pFuncArray[i],proc);
        }
        else
        {
            int idx = it - ordinalArray.begin();
            const char* name = (const char*)RVAtoVA(pNameArray[idx]);
            printf("  Func #%04i @ <%08X,%08X> w/ Name #%04i <%08X,%08X> '%s' \n",i,pFuncArray[i],proc,idx,pNameArray[idx],name,name);
            FARPROC gproc = GetProcAddress((HMODULE)moduleBase,name);
            if (gproc != proc)
            {
                printf ("    ERROR: GetProcAddress(name) returns incorrect address <%08X,%08X> with error {%08X}\n",VAtoRVA(gproc),gproc, GetLastError()); 
            }
            gproc = GetProcAddress((HMODULE)moduleBase,(LPCSTR)(i+exportDir.Base));
            if (gproc != proc)
            {
                printf ("    ERROR: GetProcAddress(ordinal) returns incorrect address <%08X,%08X> with error {%08X}\n",VAtoRVA(gproc),gproc, GetLastError()); 
            }
        }
    }
    // validate name & ordinal arrays
    printf("Sanity Check on Name & Ordinal Arrays:\n");
    if (ordinalArray.size() != pNameArray.size()) printf ("  ERROR: Ordinal Array doesn't Name array in size\n"); 
    for (unsigned int i = 0; i < ordinalArray.size(); i++) 
    {
        if (ordinalArray[i] >= pFuncArray.size()) printf ("  ERROR: Ordinal Array element #%04i = (%04i), out of bounds",i,ordinalArray[i]); 
    }
    for (unsigned int i = 0; i < pNameArray.size(); i++) 
    {
        if (pNameArray[i] == NULL) printf ("  ERROR: Name Array element #%04i is NULL, may generate error on string comparison",i); 
    }
    // validate directory
    printf("Sanity Check on Export Directory Structure:\n");
    printf("  Characteristics = {%08X}\n", exportDir.Characteristics);
    printf("  Time Stamp = {%08X}\n", exportDir.TimeDateStamp);
    printf("  Version = {%04X.%04X}\n", exportDir.MajorVersion,exportDir.MinorVersion);
    printf("  Base Ordinal = %i\n", exportDir.Base);
    if (exportDir.Name != VAtoRVA(moduleName)) 
        printf ("  ERROR: Incorrect module name RVA <%08X,%08X> != <%08X,%08X>\n",exportDir.Name,RVAtoVA(exportDir.Name),VAtoRVA(moduleName),moduleName);     
    if (exportDir.NumberOfFunctions != pFuncArray.size()) 
        printf ("  ERROR: Incorrect function array size %i != %i \n",exportDir.NumberOfFunctions,pFuncArray.size()); 
    if (exportDir.NumberOfNames != pNameArray.size()) 
        printf ("  ERROR: Incorrect name array size %i != %i \n",exportDir.NumberOfFunctions,pFuncArray.size()); 
    if (pFuncArray.size() == 0 && exportDir.AddressOfFunctions != NULL) 
        printf ("  ERROR: Incorrect Function array RVA <%08X,%08X> != <NULL,NULL>\n",exportDir.AddressOfFunctions,RVAtoVA(exportDir.AddressOfFunctions)); 
    if (pFuncArray.size() > 0 && exportDir.AddressOfFunctions != VAtoRVA(&pFuncArray[0])) 
        printf ("  ERROR: Incorrect Function array RVA <%08X,%08X> != <%08X,%08X>\n",
        exportDir.AddressOfFunctions,RVAtoVA(exportDir.AddressOfFunctions),VAtoRVA(&pFuncArray[0]),&pFuncArray[0]); 
    if (pNameArray.size() == 0 && exportDir.AddressOfNames != NULL) 
        printf ("  ERROR: Incorrect Name array RVA <%08X,%08X> != <NULL,NULL>\n",exportDir.AddressOfNames,RVAtoVA(exportDir.AddressOfNames)); 
    if (pNameArray.size() > 0 && exportDir.AddressOfNames != VAtoRVA(&pNameArray[0])) 
        printf ("  ERROR: Incorrect Name array RVA <%08X,%08X> != <%08X,%08X>\n",
        exportDir.AddressOfNames,RVAtoVA(exportDir.AddressOfNames),VAtoRVA(&pNameArray[0]),&pNameArray[0]); 
    if (ordinalArray.size() == 0 && exportDir.AddressOfNameOrdinals != NULL) 
        printf ("  ERROR: Incorrect Ordinal array RVA <%08X,%08X> != <NULL,NULL>\n",exportDir.AddressOfNameOrdinals,RVAtoVA(exportDir.AddressOfNameOrdinals)); 
    if (ordinalArray.size() > 0 && exportDir.AddressOfNameOrdinals != VAtoRVA(&ordinalArray[0])) 
        printf ("  ERROR: Incorrect Ordinal array RVA <%08X,%08X> != <%08X,%08X>\n",
        exportDir.AddressOfNameOrdinals,RVAtoVA(exportDir.AddressOfNameOrdinals),VAtoRVA(&ordinalArray[0]),&ordinalArray[0]); 
    // validate directory entry
    printf("Sanity Check on Export Directory Entry @ <%08X>:\n",exportData);
    if (exportData)
    {        
        if (exportData->VirtualAddress != VAtoRVA(&exportDir)) 
            printf ("  ERROR: Incorrect Directory Data RVA <%08X,%08X> != <%08X,%08X>\n",
            exportData->VirtualAddress,RVAtoVA(exportData->VirtualAddress),VAtoRVA(&exportDir),&exportDir);     
        if (exportData->Size != sizeof(*this)) 
            printf ("  ERROR: Incorrect Directory Data Size %04X != %04X\n",exportData->Size,sizeof(*this)); 
    }
    // done
    printf("ExportManager Debug Dump complete\n");
}

