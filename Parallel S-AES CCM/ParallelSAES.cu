#include "ParallelSAES.cuh"
#include "RoundKey.cuh"
#include "FileReader.h"
#include <iostream>
#include <cmath>

/**
* Encrypt with Counter with Cipher Block Chaining - Message
* Sequentially generates CMAC using paralellized 16 bit S-AES.
* Counter mode is generated in parallel.
* Returns the cipher text including the tag as a binary array.
*/
int* ParallelSAES::encryptCCM(string plainText, int& cipherTextLength) {

	//Plain Text to Binary
	int Plen = plainText.length() * 8;
	int plenFormatted = 0; //is a multiple of 16
	int* P = stringToBinaryArray(plainText, plenFormatted); // P is padded

	//Tag 
	int Tlen = 13;

	//Cipher
	cipherTextLength = Plen + Tlen;
	int* C = new int[cipherTextLength] {0};

	//Nonce
	int nonceLength = 16;
	int nonce[16] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1 };

	//S-AES Key rounds 
	int K0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* K1 = getRoundKey(K0, 0);
	int* K2 = getRoundKey(K1, 1);
	int* K3 = getRoundKey(K2, 2);

	//Device Pointers
	int* d_T = 0;
	int* d_P = 0;
	int* d_C = 0;
	int* d_K0 = 0;
	int* d_K1 = 0;
	int* d_K2 = 0;
	int* d_K3 = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_T, Tlen * sizeof(int));
	cudaMalloc((void**)&d_P, Plen * sizeof(int));
	cudaMalloc((void**)&d_C, cipherTextLength* sizeof(int));
	cudaMalloc((void**)&d_K0, 16 * sizeof(int));
	cudaMalloc((void**)&d_K1, 16 * sizeof(int));
	cudaMalloc((void**)&d_K2, 16 * sizeof(int));
	cudaMalloc((void**)&d_K3, 16 * sizeof(int));

	//Copy to gpu 
	cudaMemcpy(d_P, P, Plen* sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_C, C, cipherTextLength* sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K0, K0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K1, K1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K2, K2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K3, K3, 16 * sizeof(int), cudaMemcpyHostToDevice);

	//Generate Tag and copy it to gpu
	int* T = generateCMAC(P, plenFormatted, nonce, Tlen, d_K0, d_K1, d_K2, d_K3);
	cudaMemcpy(d_T, T, Tlen * sizeof(int), cudaMemcpyHostToDevice);

	//Counter Block Encryption
	int m = (ceil(Plen * 1.0 / 16));
	int* d_S = generateCounterBlockStream(m, d_K0, d_K1, d_K2, d_K3); // S0 || S1 || .. Sm
	
	//Last step of algorithm in parallel
	generateCCMOutput << <cipherTextLength, 1 >> > (d_P, Plen, d_T, d_S, d_C); 	// C  = (P xor MSB_plen(S))|| (T xor MSB_tlen(S0))
	cudaDeviceSynchronize();
	cudaMemcpy(C, d_C, cipherTextLength * sizeof(int), cudaMemcpyDeviceToHost);

	//Free cuda
	cudaDeviceReset();

	return C;
}

/**
* Decrypt with Counter with Cipher Block Chaining - Message
* Counter mode is generated in parallel.
* Sequentially generates CMAC using paralellized 16 bit S-AES.
* Returns the plain text including the tag.
* Variable @isValid tells if tags are the same.
*/
string ParallelSAES::decryptCCM(int* C, int Clen, bool& isValid) {

	//Nonce
	int nonce[16] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1 };

	//Tag
	int Tlen = 13;
	int* T = new int[Tlen] {0};

	//Plain Text
	int Plen = Clen - Tlen;
	int plenFormatted = ceil(Plen * 1.0 / 16) * 16; //plenFormatted is a multiple of 16
	int* P = new int[plenFormatted] {0}; //P is padded for SAES

	//S-AES Key rounds 
	int K0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* K1 = getRoundKey(K0, 0);
	int* K2 = getRoundKey(K1, 1);
	int* K3 = getRoundKey(K2, 2);

	//Device Pointers
	int* d_T = 0;
	int* d_P = 0;
	int* d_C = 0;
	int* d_K0 = 0;
	int* d_K1 = 0;
	int* d_K2 = 0;
	int* d_K3 = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_T, Tlen * sizeof(int));
	cudaMalloc((void**)&d_P, Plen * sizeof(int));
	cudaMalloc((void**)&d_P, Plen * sizeof(int));
	cudaMalloc((void**)&d_C, Clen * sizeof(int));
	cudaMalloc((void**)&d_K0, 16 * sizeof(int));
	cudaMalloc((void**)&d_K1, 16 * sizeof(int));
	cudaMalloc((void**)&d_K2, 16 * sizeof(int));
	cudaMalloc((void**)&d_K3, 16 * sizeof(int));

	//Cuda copy
	cudaMemcpy(d_P, P, Plen * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_C, C, Clen * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K0, K0, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K1, K1, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K2, K2, 16 * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_K3, K3, 16 * sizeof(int), cudaMemcpyHostToDevice);

	//Counter Generation Function
	int m = ceil(Clen * 1.0 / 16);
	int* d_S = generateCounterBlockStream(m, d_K0, d_K1, d_K2, d_K3);

	//Decrypt the cipher and Tag in Parallel
	extractTextAndTagCCM<<<Plen + Tlen,1>>>(d_P, Plen, d_T, d_S, d_C);
	cudaDeviceSynchronize();
	cudaMemcpy(P, d_P, Plen * sizeof(int), cudaMemcpyDeviceToHost);
	cudaMemcpy(T, d_T, Tlen * sizeof(int), cudaMemcpyDeviceToHost);

	//Convert Binary to Text
	string plainText = binaryArrayToString(P, plenFormatted);

	//Generate tag for the decrypted plain text 
	int* T1 = generateCMAC(P, plenFormatted, nonce, Tlen, d_K0, d_K1, d_K2, d_K3);

	//Compare and print tags
	bool areSame = true;
	cout << "Tag 1\t\t Tag 2";
	for (int i = 0; i < Tlen; ++i) {
		if (areSame && T[i] != T1[i]) {
			areSame = false;
			//once kjo bohet false nuk hina mo ne if
		}
		cout << T1[i] << "\t\t" << T[i] << endl;
	}
	isValid = areSame;

	//Cuda Free
	cudaDeviceReset();

	return plainText;
}

/** CMAC algorithm in CCM.
*	Sequentially generates CMAC using paralellized 16 bit S-AES.
*	Used both in encryption and decryption.
*	Array A is in binary and must be padded.
*	arrayLength must be divisible by 16.
*	Pass the device(GPU) pointers of SAES key rounds.
*	Returns the tag T.
*/
int* generateCMAC(int* A, int arrayLength, int* nonce, int Tlen, int* d_K0, int* d_K1, int* d_K2, int* d_K3) {

	int L[16] = { 0 }; //Bi xor Y_i-1, this will be sent to GPU
	int* Y = new int[arrayLength] {0};
	int r = arrayLength / 16;

	//Device pointers
	int* d_L = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_L, 16 * sizeof(int));

	for (int i = -1; i < r; i++) { //0 1 ,,, r, gjithsej r+1 . i=-1 eshte per Y0

		for (int j = 0; j < 16; j++) {
			if (i == -1) {
				L[j] = nonce[j]; //Y0
			}
			else {
				L[j] = (A[i * 16 + j] + Y[j]) % 2;
			}
		}

		//Memory Copy
		cudaMemcpy(d_L, L, 16 * sizeof(int), cudaMemcpyHostToDevice);

		//Launch Kernel
		cudaEncrypt << < 1, 16 >> > (d_L, d_K0, d_K1, d_K2, d_K3); //Y_i = E(K,L);

		//Wait for cuda
		cudaDeviceSynchronize();

		//Get Results from cudo
		cudaMemcpy(Y, d_L, 16 * sizeof(int), cudaMemcpyDeviceToHost);
	}

	cudaFree(d_L);

	//Tag
	int* T = new int[Tlen] {0};
	for (int i = 0; i < Tlen; i++) {
		T[i] = Y[i];
	}
	return T;
}

/*
* Counter generation function to generate counter blocks in parallel.
* Writes blocks S0 || S1 || S2 ||.... ||Sm into S in GPU.
* Generates m+1 counters.
* Each block Sj = E(K,Ctrj).
* The encryption function is E = Simplified AES;
* Initial Value of counter is 0.
* Used in CCM in both encryption and decryption.
* Pass the device(GPU) pointers of SAES key rounds.
*/
int* generateCounterBlockStream(int m, int* d_K0, int* d_K1, int* d_K2, int* d_K3) {

	int Slen = (m + 1) * 16; //S0, S1, ..., SM prandaj gjithsej (m+1)16
	int* S = new int[Slen] {0};

	//Device Pointer
	int* d_S = 0;

	//Memory Allocation
	cudaMalloc((void**)&d_S, Slen * sizeof(int));

	//Memory Copy
	cudaMemcpy(d_S, S, Slen * sizeof(int), cudaMemcpyHostToDevice);

	//Launch Kernel
	cudaCounterBlockEncrypt << <m + 1, 16 >> > (d_S, d_K0, d_K1, d_K2, d_K3); //S0,S1,....Sm, prandaj m+1

	//Wait for cuda
	cudaDeviceSynchronize();

	//Copy results back
	cudaMemcpy(S, d_S, Slen * sizeof(int), cudaMemcpyDeviceToHost); // S = S0 || S1 || S2 || ........|| Sm

	return d_S;
}


string ParallelSAES::encrypt(string plainText) {
	cudaError_t err = cudaSuccess;

	//Key rounds 
	int K0[16] = { 1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1 };
	int* K1 = getRoundKey(K0, 0);
	int* K2 = getRoundKey(K1, 1);
	int* K3 = getRoundKey(K2, 2);;

	//Cipher Text

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

	int gridSize = arrayLength;
	cout << "\n\Total threads "
		<< gridSize;


	cudaEncrypt << <arrayLength / 16, 16 >> > (d_A, d_K0, d_K1, d_K2, d_K3);

	//Wait for cuda
	err = cudaDeviceSynchronize();

	cout << "hola it enkript";

	//Get back the decrypted
	cudaMemcpy(A, d_A, arrayLength * sizeof(int), cudaMemcpyDeviceToHost);

	string encryptedText = binaryArrayToString(A, arrayLength);

	cudaFree(d_A);
	cudaFree(d_K0);
	cudaFree(d_K1);
	cudaFree(d_K2);

	//delete[] A;
	//delete[] K0;
	//delete[] K1;
	//delete[] K2;
	//delete[] K3;
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

	cout << "hola it dekript";


	//Get back the decrypted
	cudaMemcpy(A, d_A, arrayLength * sizeof(int), cudaMemcpyDeviceToHost);


	string decryptedText = binaryArrayToString(A, arrayLength);

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

/*
* Returns binary representation array of any string.
* The returned binary array returned will be padded, i.e the length of it will be a multiple of 16
*/
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

