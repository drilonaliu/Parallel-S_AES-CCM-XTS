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
__global__ void cudaEncrypt(int* A, int* K0, int* K1, int* K2, int* K3);
__global__ void cudaDecrypt(int* A, int* K0, int* K1, int* K2, int* K3);

//SBOX
__device__ int getSBOXsubstitution(int bitID, int* B);
__device__ int getInvSBOXsubstitution(int bitID, int* B);

//Galois Field
__device__ void addition(int* x, int* y,int* rez);
__device__ void product(int* x, int* y, int* rez);
__device__ int* reduce(int* x);
__device__   int xOr(int x, int y);
__device__   int and (int x, int y);

//Helper functionss
__device__ void sliceArray(int* arr, int part, int* x);

