#include "cuda_runtime.h"
#include "device_launch_parameters.h"


__device__ int SBox[4][4][4] = {
	 {{0, 1, 1, 0}, {1, 0, 1, 1}, {0, 0, 0, 0}, {0, 1, 0, 0}},
	 {{0, 1, 1, 1}, {1, 1, 1, 0}, {0, 0, 1, 0}, {1, 1, 1, 1}},
	 {{1, 0, 0, 1}, {1, 0, 0, 0}, {1, 0, 1, 0}, {1, 1, 0, 0}},
	 {{0, 0, 1, 1}, {0, 0, 0, 1}, {0, 1, 0, 1}, {1, 1, 0, 1}}
};


__device__ int invSBox[4][4][4] = {
	 {{0, 0, 1, 0}, {1, 1, 0, 1}, {0, 1, 1, 0}, {1, 1, 0, 0}},
	 {{0, 0, 1, 1}, {1, 1, 1, 0}, {0, 0, 0, 0}, {0, 1, 0, 0}},
	 {{1, 0, 0, 1}, {1, 0, 0, 0}, {1, 0, 1, 0}, {0, 0, 0, 1}},
	 {{1, 0, 1, 1}, {1, 1, 1, 1}, {0, 1, 0, 1}, {0, 1, 1, 1}}
};

//Kernels
__global__ void cudaXTSencrypt(int* P, int* C, bool cipherSteal, int m,  int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3);
__global__ void cudaXTSdecrypt(int* P, int* C, bool cipherSteal, int m,  int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3);
__device__ void XTSBlockEncrypt(int threadId, int blockId, int textIndex, int* P, int* C, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3);
__device__ void XTSBlockDecrypt(int threadId, int blockId, int textIndex, int* P, int* C, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3);


//S - AES
__device__ void SAESencrypt(int i, int plainTextIndex, int* A, int* K0, int* K1, int* K2, int* K3);
__device__ void SAESdecrypt(int i, int plainTextIndex, int* A, int* K0, int* K1, int* K2, int* K3);
__device__ int getSBOXsubstitution(int bitID, int* B);
__device__ int getInvSBOXsubstitution(int bitID, int* B);

//Galois Field
__device__ void product16(int* x, int* y, int* reduced);
__device__ void addition(int* x, int* y,int* rez);
__device__ void product(int* x, int* y, int* rez);
__device__   int xOr(int x, int y);
__device__   int and (int x, int y);

//Helper functions
__device__ void sliceArray(int* arr, int part, int* x);
__device__ void toBinaryArray(int num, int* binaryArray);

