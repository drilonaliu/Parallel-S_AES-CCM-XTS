#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <string>
#include "KernelSAES.cuh"
using namespace std;

class ParallelSAES {

public:
	string encrypt(string plainText);
	string decrypt(string plainText);
};

string binaryArrayToString(int* binaryArray, int arrayLength);
int* stringToBinaryArray(const string& input, int& arrayLength);