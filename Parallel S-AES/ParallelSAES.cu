#include "ParallelSAES.cuh"
#include "RoundKey.cuh"
#include "FileReader.h"
#include <iostream>


string ParallelSAES::encrypt(string plainText) {

	//Key rounds 
	int K0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* K1 = getRoundKey(K0, 0);
	int* K2 = getRoundKey(K1, 1);
	int* K3 = getRoundKey(K2, 2);;


	//int A[16] = { 1,0,1,0,1,1,1,0,0,0,1,0,0,1,0,0 }; //shtojca A!

	int arrayLength = 0;
	int* A = stringToBinaryArray(plainText, arrayLength);


	//Device Pointers
	int* d_A = 0;
	int* d_K0 = 0;
	int* d_K1 = 0;
	int* d_K2 = 0;
	int* d_K3 = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_A, arrayLength * sizeof(int));
	cudaMalloc((void**)&d_K0, 16 * sizeof(int));
	cudaMalloc((void**)&d_K1, 16 * sizeof(int));
	cudaMalloc((void**)&d_K2, 16 * sizeof(int));
	cudaMalloc((void**)&d_K3, 16 * sizeof(int));

	//CudaMemcpy
	cudaMemcpy(d_A, A, arrayLength * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K0, K0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K1, K1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K2, K2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K3, K3, 16 * sizeof(int), cudaMemcpyHostToDevice);


	//Launch Kernel
	int threadsPerBlock = 16;
	int blocksPerGrid = arrayLength / 16;
	cudaEncrypt << <blocksPerGrid, threadsPerBlock >> > (d_A, d_K0, d_K1, d_K2, d_K3);

	//Wait for cuda
	cudaDeviceSynchronize();

	//Get back the decrypted
	cudaMemcpy(A, d_A, arrayLength * sizeof(int), cudaMemcpyDeviceToHost);

	//Convert the binary to text 
	string encryptedText = binaryArrayToString(A, arrayLength);

	//Free memory
	cudaFree(d_A);
	cudaFree(d_K0);
	cudaFree(d_K1);
	cudaFree(d_K2);

	return encryptedText;
}

string ParallelSAES::decrypt(string cipher) {
	//Key rounds 
	int K0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* K1 = getRoundKey(K0, 0);
	int* K2 = getRoundKey(K1, 1);
	int* K3 = getRoundKey(K2, 2);;

	//Cipher Text
	int arrayLength = 0;
	int* A = stringToBinaryArray(cipher, arrayLength);
	//int A[16] = { 0,0,1,1,0,0,1,0,0,1,1,1,0,0,1,0 }; SHTOJCA A!


	//Device Pointers
	int* d_A = 0;
	int* d_K0 = 0;
	int* d_K1 = 0;
	int* d_K2 = 0;
	int* d_K3 = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_A, arrayLength * sizeof(int));
	cudaMalloc((void**)&d_K0, 16 * sizeof(int));
	cudaMalloc((void**)&d_K1, 16 * sizeof(int));
	cudaMalloc((void**)&d_K2, 16 * sizeof(int));
	cudaMalloc((void**)&d_K3, 16 * sizeof(int));

	//CudaMemcpy
	cudaMemcpy(d_A, A, arrayLength * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K0, K0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K1, K1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K2, K2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K3, K3, 16 * sizeof(int), cudaMemcpyHostToDevice);


	//Launch Kernel
	cudaDecrypt << <arrayLength / 16, 16 >> > (d_A, d_K0, d_K1, d_K2, d_K3);

	//Wait for cuda
	cudaDeviceSynchronize();

	//Get back the decrypted
	cudaMemcpy(A, d_A, arrayLength * sizeof(int), cudaMemcpyDeviceToHost);

	//Convert  binary to text
	string decryptedText = binaryArrayToString(A, arrayLength);


	//Free memory
	cudaFree(d_A);
	cudaFree(d_K0);
	cudaFree(d_K1);
	cudaFree(d_K2);

	return decryptedText;;
}

string binaryArrayToString(int* binaryArray, int arrayLength) {
	string result;
	for (int i = 0; i < arrayLength; i += 8) {
		char c = 0;
		for (int j = 0; j < 8; j++) {
			c = (c << 1) | binaryArray[i + j];
		}
		result += c;
	}
	return result;
}


int* stringToBinaryArray(const string& input, int& arrayLength) {
	arrayLength = input.length() * 8;

	//Padding
	if (arrayLength % 16 != 0) {
		arrayLength += 16 - (arrayLength % 16);
	}

	int* binaryArray = new int[arrayLength] {0}; // Each character is 8 bits)

	int index = 0;
	for (char c : input) {
		// Convert each character to its binary representation
		for (int i = 7; i >= 0; i--) {
			binaryArray[index] = (c & (1 << i)) ? 1 : 0;
			index++;
		}
	}
	return binaryArray;
}