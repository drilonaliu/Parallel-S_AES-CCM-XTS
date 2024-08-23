#include "ParallelSAES.cuh"
#include "RoundKey.cuh"
#include "FileReader.h"
#include <iostream>



int* ParallelSAES::encryptXTS(string plainText, int& plainTextLength) {

	//Key 1
	int Key1_0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* Key1_1 = getRoundKey(Key1_0, 0);
	int* Key1_2 = getRoundKey(Key1_1, 1);
	int* Key1_3 = getRoundKey(Key1_2, 2);

	//Key2
	int Key2_0[16] = { 1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0 };
	int* Key2_1 = getRoundKey(Key2_0, 0);
	int* Key2_2 = getRoundKey(Key2_1, 1);
	int* Key2_3 = getRoundKey(Key2_2, 2);

	//Initial tweak value 
	int Tweak0[16] = { 1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0 };

	//PlainText to Binary
	int arrayLength = 0;
	int* P = stringToBinaryArray(plainText, arrayLength);
	plainTextLength = arrayLength;

	cout << "\n\nPlain text has: "
		<< arrayLength
		<< " characters"; 

	cout << "\n\nPlainText to binary: \n\n";
	for (int i = 0; i < arrayLength; i++) {
		cout << P[i];
	}

	//Cipher Text 
	int cipherTextLength = plainText.length() * 8;
	int* C = new int[cipherTextLength];

	//CipherStealing
	bool cipherSteal = false;
	if ((plainText.length() * 8) % 16 != 0) {
		cipherSteal = true;
	}

	cout << "\n\nCipher stealing is needed? : "
		<< cipherSteal;

	//Number of blocks to launch = m 
	int m = cipherTextLength / 16;

	//Device Pointers
	int* d_P = 0;
	int* d_C = 0;
	int* d_Tweak0 = 0;
	int* d_Key1_0 = 0;
	int* d_Key1_1 = 0;
	int* d_Key1_2 = 0;
	int* d_Key1_3 = 0;
	int* d_Key2_0 = 0;
	int* d_Key2_1 = 0;
	int* d_Key2_2 = 0;
	int* d_Key2_3 = 0;

	//Memory Allocations
	cudaMalloc((void**)&d_P, arrayLength * sizeof(int));
	cudaMalloc((void**)&d_C, cipherTextLength * sizeof(int));
	cudaMalloc((void**)&d_Tweak0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_1, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_2, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_3, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_1, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_2, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_3, 16 * sizeof(int));

	//Memory copy
	cudaMemcpy(d_P, P, arrayLength * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_0, Key1_0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_1, Key1_1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_2, Key1_2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_3, Key1_3, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_0, Key2_0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_1, Key2_1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_2, Key2_2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_3, Key2_3, 16 * sizeof(int), cudaMemcpyHostToDevice);

	//Launch Kernel 
	cudaXTSencrypt << <cipherTextLength / 16, 16 >> > (d_P, d_C, cipherSteal, m, d_Tweak0, d_Key1_0, d_Key1_1, d_Key1_2, d_Key1_3, d_Key2_0, d_Key2_1, d_Key2_2, d_Key2_3);

	//Wait for cuda to finish
	cudaDeviceSynchronize();

	//Copy cipher from GPU
	cudaMemcpy(C, d_C, cipherTextLength * sizeof(int), cudaMemcpyDeviceToHost);

	//Free cuda 
	cudaFree(d_P);
	cudaFree(d_C);

	cout << "\n\nEncrypted in binary: \n\n";
	for (int i = 0; i < arrayLength; i++) {
		cout << C[i];
	}

	return C;
}


string ParallelSAES::decryptXTS(int* cipher, int cipherTextLength) {

	//Key 1
	int Key1_0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* Key1_1 = getRoundKey(Key1_0, 0);
	int* Key1_2 = getRoundKey(Key1_1, 1);
	int* Key1_3 = getRoundKey(Key1_2, 2);

	//Key2
	int  Key2_0[16] = { 1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0 };
	int* Key2_1 = getRoundKey(Key2_0, 0);
	int* Key2_2 = getRoundKey(Key2_1, 1);
	int* Key2_3 = getRoundKey(Key2_2, 2);

	//Initial tweak value 
	int Tweak0[16] = { 1,0,0,1,1,1,1,0,1,0,1,1,1,0,1,0 };

	//Plain Text 
	int arrayLength = cipherTextLength;
	int* P = new int[cipherTextLength];

	//Cipher Stealing 
	bool cipherSteal = false;
	if (cipherTextLength % 16 != 0) {
		cipherSteal = true;
	}

	//Number of blocks to launch = m 
	int m = cipherTextLength / 16;

	//Device Pointers
	int* d_C = 0;
	int* d_P = 0;
	int* d_Tweak0 = 0;
	int* d_Key1_0 = 0;
	int* d_Key1_1 = 0;
	int* d_Key1_2 = 0;
	int* d_Key1_3 = 0;
	int* d_Key2_0 = 0;
	int* d_Key2_1 = 0;
	int* d_Key2_2 = 0;
	int* d_Key2_3 = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_C, arrayLength * sizeof(int));
	cudaMalloc((void**)&d_P, arrayLength * sizeof(int));
	cudaMalloc((void**)&d_Tweak0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_1, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_2, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key1_3, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_0, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_1, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_2, 16 * sizeof(int));
	cudaMalloc((void**)&d_Key2_3, 16 * sizeof(int));

	//Memory copy
	cudaMemcpy(d_C, cipher, arrayLength * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_0, Key1_0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_1, Key1_1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_2, Key1_2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key1_3, Key1_3, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_0, Key2_0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_1, Key2_1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_2, Key2_2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_Key2_3, Key2_3, 16 * sizeof(int), cudaMemcpyHostToDevice);

	//Launch Kernel
	cudaXTSdecrypt << <arrayLength / 16, 16 >> > (d_P, d_C, cipherSteal, m, d_Tweak0, d_Key1_0, d_Key1_1, d_Key1_2, d_Key1_3, d_Key2_0, d_Key2_1, d_Key2_2, d_Key2_3);

	//Wait for cuda
	cudaDeviceSynchronize();


	//Copy back the result
	cudaMemcpy(cipher, d_P, arrayLength * sizeof(int), cudaMemcpyDeviceToHost);

	cout << "\n\nDecrypted in binary: \n\n";
	for (int i = 0; i < arrayLength; i++) {
		cout << cipher[i];
	}

	//Convert the binary to string
	string decrypted = binaryArrayToString(cipher, arrayLength);

	return decrypted;
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
	//if (arrayLength % 16 != 0) {
	//	arrayLength += 16 - (arrayLength % 16);
	//}

	//printf("\n\nArrayLength is  = %d", arrayLength);
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