/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m    <module_name> ; Analysed module name (by default same as app name)
* -o    <output_path> Output file
*
* saves PID in <output_file>.pid
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include "stdio.h"
#include<cwchar> 
#define TOOL_NAME "TinyTracer"
#ifndef PAGE_SIZE
    #define PAGE_SIZE 0x1000
#endif
using namespace std;


/* ================================================================== */
// Global variables 
/* ================================================================== */
constexpr int maxNamArgs = 3;
struct Function
{
	string          functionName;
	uint32_t        numArgs;
	vector<string>  argsTypes;
};

vector<Function> functions;

vector<Function> defence_functions;

ifstream fileListFunctions("FileListFunctions.txt", ios_base::in);
ofstream fileFunctionsLog("FileFunctionsLog.txt", ios_base::out);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "specify file name for the output");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

KNOB<bool> KnobShortLog(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Use short call logging (without a full DLL path)");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
    cerr << "This tool prints out : " << endl <<
        "Addresses of redirections into to a new sections. Called API functions.\n" << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
* This function is called for every basic block when it is about to be executed.
* @param[in]   numInstInBbl    number of instructions in the basic block
* @note use atomic operations for multi-threaded applications
*/

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
* Insert call to the SaveTranitions() analysis routine before every basic block
* of the trace.
* This function is called every time a new trace is encountered.
* @param[in]   trace    trace to be instrumented
* @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
*                       function call
*/


UINT __stdcall GetTickCount() {
	fileFunctionsLog << "Returned zero.\n";
	return (UINT)0;
}

bool __stdcall IsDebuggerPresent() {
	fileFunctionsLog << "Change IsDebuggerPresent value to false: compelete.\n";
	return false;
}

VOID zeroArgsFunc(char* funcName, ADDRINT address)
{
	fileFunctionsLog << "Function: " << funcName << " Address: " << address << '\n';
}
VOID oneArgsFunc(char* funcName, ADDRINT address, ADDRINT arg1)
{
	fileFunctionsLog << "Function: " << funcName << " Address: " << address << " Args: ";
	for (auto it = functions.begin(); it != functions.end(); ++it)
	{
		if (it->functionName == funcName)
		{
			if (it->argsTypes[0] == string("string"))
			{
				fileFunctionsLog << (char*)arg1;
			}else if (it->argsTypes[0] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg1);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg1;
			}
		}
	}
	fileFunctionsLog <<'\n';
}
VOID twoArgsFunc(char* funcName, ADDRINT address, ADDRINT arg1, ADDRINT  arg2)
{
	fileFunctionsLog << "Function: " << funcName << " Address: " << address << " Args: ";
	for (auto it = functions.begin(); it != functions.end(); ++it)
	{
		if (it->functionName == funcName)
		{
			if (it->argsTypes[0] == string("string"))
			{
				fileFunctionsLog << (char*)arg1;
			}
			else if (it->argsTypes[0] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg1);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg1;
			}
			fileFunctionsLog << " ";
			if (it->argsTypes[1] == string("string"))
			{
				fileFunctionsLog << (char*)arg2;
			}
			else if (it->argsTypes[1] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg2);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg2;
			}
		}
	}
	fileFunctionsLog << '\n';

}
VOID threeArgsFunc(char* funcName, ADDRINT address, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3)
{
	fileFunctionsLog << "Function: " << funcName << " Address: " << address << " Args: ";
	for (auto it = functions.begin(); it != functions.end(); ++it)
	{
		if (it->functionName == funcName)
		{
			if (it->argsTypes[0] == string("string"))
			{
				fileFunctionsLog << (char*)arg1;
			}
			else if (it->argsTypes[0] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg1);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg1;
			}
			fileFunctionsLog << " ";
			if (it->argsTypes[1] == string("string"))
			{
				fileFunctionsLog << (char*)arg2;
			}
			else if (it->argsTypes[1] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg2);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg2;
			}
			fileFunctionsLog << " ";
			if (it->argsTypes[2] == string("string"))
			{
				fileFunctionsLog << (char*)arg3;
			}
			else if (it->argsTypes[2] == string("wstring"))
			{
				wstring tempWString = wstring((wchar_t*)arg3);
				string  tempString = string(tempWString.begin(), tempWString.end());
				fileFunctionsLog << tempString;
			}
			else
			{
				fileFunctionsLog << arg3;
			}
		}
	}
	fileFunctionsLog << '\n';
}
VOID ImageLoad(IMG Image, VOID* v)
{
	PIN_LockClient();
	RTN funcRtn; 
	for (auto it = functions.begin(); it != functions.end(); ++it)
	{
		funcRtn = RTN_FindByName(Image, it->functionName.c_str());
		if (RTN_Valid(funcRtn)) {
			RTN_Open(funcRtn);
			switch (it->numArgs)
			{
			case 0:
				RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)zeroArgsFunc,
					IARG_ADDRINT, it->functionName.c_str(),
					IARG_INST_PTR,
					IARG_END);
				break;
			case 1:
				RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)oneArgsFunc,
					IARG_ADDRINT, it->functionName.c_str(),
					IARG_INST_PTR,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_END);
				break;
			case 2:
				RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)twoArgsFunc,
					IARG_ADDRINT, it->functionName.c_str(),
					IARG_INST_PTR,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_END);
				break;
			case 3:
				RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)threeArgsFunc,
					IARG_ADDRINT, it->functionName.c_str(),
					IARG_INST_PTR,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
					IARG_END);
				break;
			}
			RTN_Close(funcRtn);
		}
	}
	PIN_UnlockClient();

}
/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/


int main(int argc, char *argv[])
{
	std::string line;

	printf("Hello from pin!\n");
	// Записали отслеживаемые функции
	if (fileListFunctions.is_open())
	{
		while (getline(fileListFunctions, line))
		{
			istringstream lineStream(line);
			Function function;
			string numArgs;
			getline(lineStream, function.functionName, ';');
			getline(lineStream, numArgs, ';');
			uint32_t numArgsInt = atoi(numArgs.c_str());
			function.numArgs = numArgsInt;
			for (uint32_t i = 0; i < numArgsInt; i++)
			{
				string argType;
				getline(lineStream, argType, ';');
				function.argsTypes.push_back(argType);
			}
			fileFunctionsLog << "Function: " << function.functionName << " ArgsNum : " << function.numArgs << " ArgsType: ";
			functions.push_back(function);
			for (uint32_t i = 0; i < numArgsInt; i++)
			{
				fileFunctionsLog << ' ' << function.argsTypes[i];
			}
			fileFunctionsLog << '\n';
		}
	}
	fileListFunctions.close();

	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	IMG_AddInstrumentFunction(ImageLoad, 0);
	PIN_StartProgram();
	fileFunctionsLog.close();
	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

