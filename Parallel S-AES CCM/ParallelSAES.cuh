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
	int* encryptCCM(string plainText, int& cipherTextLength);
	string decryptCCM(int* C, int Clen,bool& isValid);
};

//Helper Functions
string binaryArrayToString(int* binaryArray, int arrayLength);
int* stringToBinaryArray(const string& input, int& arrayLength);
int* generateCounterBlockStream(int m, int* d_K0, int* d_K1, int* d_K2, int* d_K3);
int* generateCMAC(int* A, int arrayLength, int* nonce, int Tlen, int* d_K0, int* d_K1, int* d_K2, int* d_K3);