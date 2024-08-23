#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <string>
#include "KernelSAES.cuh"
using namespace std;

class ParallelSAES {

public:
	int* encryptXTS(string plainText, int& plainTextLength);
	string decryptXTS(int* cipher, int cipherTextLength);

};

int* stringToBinaryArray(const string& input, int& arrayLength);
string binaryArrayToString(int* binaryArray, int arrayLength);