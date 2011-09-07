grammar EEDGrammar;

options
{
	language = 'C';
}

tokens
{
	// tokens for unparsed but reserved keywords
	APPLOADER 		= 'APPLOADER';
	CODE 			= 'CODE';
	CONFORMING 		= 'CONFORMING';
	DESCRIPTION 	= 'DESCRIPTION';
	DEV386 			= 'DEV386';
	DISCARDABLE 	= 'DISCARDABLE';
	DYNAMIC 		= 'DYNAMIC';
	EXECUTE_ONLY 	= 'EXECUTE-ONLY';
	EXECUTEONLY 	= 'EXECUTEONLY';
	EXECUTEREAD 	= 'EXECUTEREAD';
	EXETYPE 		= 'EXETYPE';
	FIXED 			= 'FIXED';
	FUNCTIONS 		= 'FUNCTIONS';
	IMPORTS 		= 'IMPORTS';
	IMPURE 			= 'IMPURE';
	INCLUDE 		= 'INCLUDE';
	INITINSTANCE 	= 'INITINSTANCE';
	IOPL 			= 'IOPL';
	LOADONCALL 		= 'LOADONCALL';
	LONGNAMES 		= 'LONGNAMES';
	MOVABLE 		= 'MOVABLE';
	MOVEABLE 		= 'MOVEABLE';
	MULTIPLE 		= 'MULTIPLE';
	NEWFILES 		= 'NEWFILES';
	NODATA 			= 'NODATA';
	NOIOPL 			= 'NOIOPL';
	NONCONFORMING 	= 'NONCONFORMING';
	NONDISCARDABLE 	= 'NONDISCARDABLE';
	NONE 			= 'NONE';
	NONSHARED 		= 'NONSHARED';
	NOTWINDOWCOMPAT = 'NOTWINDOWCOMPAT';
	OBJECTS 		= 'OBJECTS';
	OLD 			= 'OLD';
	PRELOAD 		= 'PRELOAD';
	PROTMODE 		= 'PROTMODE';
	PURE 			= 'PURE';
	READONLY 		= 'READONLY';
	READWRITE 		= 'READWRITE';
	REALMODE 		= 'REALMODE';
	RESIDENT 		= 'RESIDENT';
	RESIDENTNAME 	= 'RESIDENTNAME';
	SINGLE 			= 'SINGLE';
	WINDOWAPI 		= 'WINDOWAPI';
	WINDOWCOMPAT 	= 'WINDOWCOMPAT';
	WINDOWS 		= 'WINDOWS';
}


@parser::includes
{
	
	#include <stdlib.h>					// string -> number parsing
	#include <iostream>					// debug output
	#include <windows.h>				// module name/handle funcs - TODO: replace
	#include <vector>					// for list of active modules
	#include "ExportManager.h"			// class def
	
	extern std::vector<unsigned long>	g_LoadingBases;		// base offset array for active modules
	extern std::vector<ExportManager*> 	g_ExportManagers;	// manager object array for active modules

}

@parser::postinclude
{
	// instantiations of global vars
	std::vector<unsigned long>	g_LoadingBases;
	std::vector<ExportManager*> g_ExportManagers;
}


@lexer::includes
{
	#include <iostream>					// debug output
}

//********************** RULES *****************************
file
	: statement*
	;

statement
	:	nameStatement
	|	baseStatement
	|	exportStatement
	|	versionStatement
	|	heapsizeStatement
	|	stacksizeStatement
	|	stubStatement
	|	sectionsStatement
	;

//**************** GROUPABLE STATEMENTS **********************	
nameStatement
@init {g_ExportManagers.clear(); g_LoadingBases.clear();}
	:	('NAME'|'LIBRARY') f0=filename {g_ExportManagers.push_back(ExportManager::GetExportManager((char*)$f0.text->chars,true));/**/printf("NAME '\%s'\n",$f0.text->chars);/**/}
		(',' f=filename {g_ExportManagers.push_back(ExportManager::GetExportManager((char*)$f.text->chars,true));/**/printf("NAME '\%s'\n",$f.text->chars);/**/} )*
		{g_LoadingBases.resize(g_ExportManagers.size(),0);}
	;
	
baseStatement
@init {g_LoadingBases.clear();}
	:	'BASE' '=' n0=number {g_LoadingBases.push_back($n0.value);/**/printf("BASE <\%08X>\n",$n0.value);/**/} 
		(',' n=number {g_LoadingBases.push_back($n.value);/**/printf("BASE <\%08X>\n",$n.value);/**/} )* 
		{g_LoadingBases.resize(g_ExportManagers.size(),0); /* force base array to proper size with default value 0x0*/}
	;
	
versionStatement
	:	'VERSION' '='versionDesc (',' versionDesc)*
	;
versionDesc : INT ('.' INT)? ;
	
exportStatement
	:	'EXPORTS' ( exportSymbol )* {/**/printf("EXPORT DONE \n");/**/}
	;	
	
exportSymbol
@declarations { std::vector<unsigned long> sources; std::vector<long> ordinals; pANTLR3_STRING symbol; int i;}
	:	SYMBOL {symbol = $SYMBOL.text;/**/printf("SYMBOL '\%s'\n",$SYMBOL.text->chars);/**/}
	( '=' s0=symbolSource[i=0] {sources.push_back($s0.addr);/**/printf("SOURCE <\%08X>\n",$s0.addr);/**/} 
		(',' s=symbolSource[++i] {sources.push_back($s.addr);/**/printf("SOURCE <\%08X>\n",$s.addr);/**/} )* 
	)? 
	( '@' n0=number {ordinals.push_back($n0.value);/**/printf("ORDINAL {\%i}\n",$n0.value);/**/} 
		(',' n=number {ordinals.push_back($n.value);/**/printf("ORDINAL {\%i}\n",$n.value);/**/} )* 
		( 'NONAME' {symbol = NULL;/**/printf("SYMBOL NONAME \n");/**/} )? 
	)? 
	'PRIVATE'? 'DATA'?
	{
		sources.resize(g_ExportManagers.size(),0);		// force source addr array to proper size with default value 0x0
		ordinals.resize(g_ExportManagers.size(),-1);	// force ordinal array to proper size with default value -1
		for (i = 0; i < g_ExportManagers.size(); i++)
		{
			// for each export manager, determine source address and ordinal and add to manager's export table
			ordinals[i] = g_ExportManagers[i]->ExportFunc((FARPROC)sources[i],ordinals[i]);
			if (symbol && ordinals[i] >= 0) g_ExportManagers[i]->ExportName((char*)symbol->chars,ordinals[i]);
		}
	}
	;
	
symbolSource[unsigned long idxModule] returns [unsigned long addr]
@declarations 
{	
	HMODULE srcModule = 0; $addr = 0; 
	if (idxModule < g_ExportManagers.size()) 
	{
		// valid module index
		srcModule = g_ExportManagers[idxModule]->GetModule(); 
		$addr -=g_LoadingBases[idxModule]; 
	}
}
	:	('#' {$addr = 0;} )? number {$addr += $number.value + (unsigned long)srcModule;/**/printf("SOURCEADDR <\%08X>\n",$number.value);/**/}
	|	SYMBOL (':' filename {srcModule = GetModuleHandle((char*)$filename.text->chars);/**/printf("SOURCEMODULE '\%s'\n",$filename.text->chars);/**/} )? 
		{$addr = srcModule ? (unsigned long)GetProcAddress(srcModule,(char*)$SYMBOL.text->chars) : 0;/**/printf("SOURCESYMBOL '\%s'\n",$SYMBOL.text->chars);/**/}
	;

//**************** SINGLE MODULE STATEMENTS *********************	
heapsizeStatement
	:	'HEAPSIZE' '=' number (',' number)?
	;
	
stacksizeStatement
	:	'STACKSIZE' '=' number (',' number)?
	;
	
stubStatement
	:	'STUB' filename
	;
	
sectionsStatement 
	:	('SECTIONS'|'SEGMENTS') ('.' SYMBOL ('READ'|'WRITE'|'EXECUTE'|'SHARED')+ )+
	;

//*********************** SUBRULES ******************************
number returns [long value]
	:	
	(	INT			{$value = strtol((char*)$INT.text->chars,NULL,10);}
	|	HEX 		{$value = strtol((char*)$HEX.text->chars,NULL,16);}
	)
	;
	
filename
	:
	(	STRING
	|	(SYMBOL|'.'|':'|'\\'|'/'|INT|HEX)+
	)
	;

//********************* LEXER TOKENS *************************************
COMMENT
    :   ';' (~('\n'|'\r'))* ('\r'|'\n'|EOF) {$channel=HIDDEN;}
    ;
    
STRING
    :  '"' ~('"'|'\n'|'\r')* '"' {SETTEXT($text->subString($text,1,$text->len-1));} 
    ;
		
HEX
	: 
	(	'0' 'x' ('0'..'9'|'a'..'f'|'A'..'F')*
	| 	('0'..'9'|'a'..'f'|'A'..'F')* 'h'	{SETTEXT($text->subString($text,0,$text->len-1));} 
	)
	;
	
INT
	:	('0'..'9')+	
    ; 
  
SYMBOL 
	:	('a'..'z'|'A'..'Z'|'_'|'?'|'$'|'@') ('a'..'z'|'A'..'Z'|'_'|'?'|'0'..'9'|'@'|'$')*
	;

fragment 
WSTOKEN 
	: ' '|'\t'|'\r'|'\n'|'\f'
	;

WHITESPACE
	:   WSTOKEN {$channel=HIDDEN;}
    ;
	
