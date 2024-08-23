#include "KernelSAES.cuh";
#include <iostream>
//#include "device_launch_parameters.h"

//for __syncthreads()
#ifndef __CUDACC__ 
#define __CUDACC__
#endif
#include <device_functions.h>


/**
* XTS method of encryption using simplified AES in parallel.
* Pass the Cipher, result will be written to P.
* Each block must operate on 16 threads.
* Key1 and Key2 are of 16 bits.
* Pass the SAES key rounds for both of keys.
* Multiplication with a^j is done in GF(2^16).
* Value of a is a = x in GF(2^16).
*
* @param P - Plain Text
* @param C - Cipher Text
* @param m - Number of total blocks 
* @param cipherSteal - True if we need to do the cipherSteal method
* @param tweak0 - Initial tweak value
* @param Key1_0, Key1_1,...Key1_3, initial SAES first key with its rounds (16bit)
*/
__global__ void cudaXTSencrypt(int* P, int* C, bool cipherSteal, int m, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3) {
	
	int i = threadIdx.x;
	int j = blockIdx.x;
	XTSBlockEncrypt(threadIdx.x, blockIdx.x, i + 16 * j, P, C, tweak0, Key1_0, Key1_1, Key1_2, Key1_3, Key2_0, Key2_1, Key2_2, Key2_3);
	__syncthreads;

	//If we need to do cipher steal technique, last block  P_m-1 takes care of it.
	if (cipherSteal && blockIdx.x == m - 1) {

		__shared__ int YY[16];
		__shared__ int C_YY[16];

		YY[i] = 0;

		//Fill YY
		if (i < 8) {
			YY[i] = P[i + 16 * m];
		}
		else {
			YY[i] = C[i + 16 * j];
		}

		__syncthreads(); //lejohet sepse sinkronizojme te gjithe threadat vetem te blockut m-1

		//Encrypt the padded plainText YY to C_YY. Encrypt as if the block m = blockIdx.x + 1 would encrypt it.
		XTSBlockEncrypt(threadIdx.x, blockIdx.x + 1, i, YY, C_YY, tweak0, Key1_0, Key1_1, Key1_2, Key1_3, Key2_0, Key2_1, Key2_2, Key2_3);
		__syncthreads();

		int temp = C[i + 16 * j];

		__syncthreads();
		//Shifting 

		// Cm goes to last position ->
		if (i < 8) {
			C[i + 16 * m] = temp; 
		}
		__syncthreads();

		//Fill C_m-1
		C[i + 16 * j] = C_YY[i];
	}

}

/**
* XTS method of decryption using simplified AES in parallel.
* Pass the cipher, result will be written on P.
* Each block must operate on 16 threads.
* Key1 and Key2 are of 16 bits.
* Pass the SAES key rounds for both of keys.
* Multiplication with a^j is done in GF(2^16).
* Value of a is a = x in GF(2^16). (0...10) = x
* 
* @param P - Plain Text
* @param C - Cipher Text
* @param m - Number of total blocks
* @param cipherSteal - True if we need to do the cipherSteal method
* @param tweak0 - Initial tweak value
* @param Key1_0, Key1_1,...Key1_3, initial SAES first key with its rounds (16bit)
*/
__global__ void cudaXTSdecrypt(int* P, int* C, bool cipherSteal, int m, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3) {

	int i = threadIdx.x;
	int j = blockIdx.x;

	//All the blocks less than m-1 will decrypt normally. If there is no cipher stealing required, then  the last block decrypt the same.
	if (blockIdx.x < m - 1 || (!cipherSteal && blockIdx.x == m - 1)) {
		XTSBlockDecrypt(threadIdx.x, blockIdx.x, i + 16 * j, P, C, tweak0, Key1_0, Key1_1, Key1_2, Key1_3, Key2_0, Key2_1, Key2_2, Key2_3);
	}
	else if (cipherSteal && blockIdx.x == m - 1) { 

		__shared__ int XX[16];
		__shared__ int P_XX[16];

	
		XTSBlockDecrypt(i, j + 1, i + 16 * j, P, C, tweak0, Key1_0, Key1_1, Key1_2, Key1_3, Key2_0, Key2_1, Key2_2, Key2_3);  //j+1 = m, 
		__syncthreads;

		P_XX[i] = 0;
		if (i < 8) {
			XX[i] = C[i + 16 * m];
		}
		else {
			XX[i] = P[i + 16 * j];
		}
		__syncthreads;
		XTSBlockDecrypt(i, j, i, P_XX, XX, tweak0, Key1_0, Key1_1, Key1_2, Key1_3, Key2_0, Key2_1, Key2_2, Key2_3); //P_m-1 is found with the inputs i, m-1 = j
		__syncthreads;

		int temp = P[i + 16 * j];
		__syncthreads;

		//Shifting 
		
		// Pm goes to last position ->
		if (i < 8) {
			P[i + 16 * m] = temp;
		}
		__syncthreads;

		//Fill P_m-1
		P[i + 16 * j] = P_XX[i];

	}
}

/*
* XTS-AES encryption operation on a singgle block.
* Encrypt 16 bits in parallel.
* 
* 
* @param P - plain text
* @param C - cipher text
* @param threadId - threadId of each block, can be any value from 0 to 15.
* @param blockId - the sequential number of the 16 bit block isnide the data unit.
* @param textIndex - which bit to read and write from in relation to threadId and blockId.
*/
__device__ void XTSBlockEncrypt(int threadId, int blockId, int textIndex, int* P, int* C, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3) {
	int i = threadId;
	int j = blockId;
	int threadIndex = i + 16 * j;//index of thread in a grid level.
	int plainTextIndex = textIndex;


	//XTS arrays
	__shared__ int binaryBlockId[16];
	__shared__ int tweak[16];
	__shared__ int aj[16]; // a to the power of j.
	__shared__ int T[16];
	//For S-AES. Threads communicate with eachother using these arrays in device method saes.
	aj[i] = 0;

	//First thread of each block converts the threadIndex in binary
	if (i == 0) {
		toBinaryArray(threadIndex, binaryBlockId);
	}
	__syncthreads;

	//First thread of each block calculates a^j
	if (i == 0) {
		int a[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0 };
		aj[14] = 1;
		for (int m = 0; m < j; m++) {
			product16(a, aj, aj);
		}
	}

	//Calculating tweak value
	tweak[i] = (tweak0[i] + binaryBlockId[i]) % 2;
	__syncthreads;

	//Start of algorithm

	//Key2 encrypts with tweak.
	SAESencrypt(i, i, tweak, Key2_0, Key2_1, Key2_2, Key2_3);
	__syncthreads;

	//T = a^j  x E(Key2,tweak);
	if (i == 0) {
		product16(tweak, aj, T);
	}
	__syncthreads;

	//PP = T xor Pj
	C[plainTextIndex] = (T[i] + P[plainTextIndex]) % 2;

	//CC = E(PP,Key1)
	SAESencrypt(i, plainTextIndex, C, Key1_0, Key1_1, Key1_2, Key1_3);
	__syncthreads;

	//Cj = CC xor T
	C[plainTextIndex] = (T[i] + C[plainTextIndex]) % 2;
}


/*
* XTS-AES decryption operation on a single block.
* Decrypts 16 bits in parallel.
*
* @param P - plain text
* @param C - cipher text
* @param threadId - threadId of each block, can be any value from 0 to 15.
* @param blockId - the sequential number of the 16 bit block isnide the data unit.
* @param textIndex - which bit to read and write from in relation to threadId and blockId.
*/
__device__ void XTSBlockDecrypt(int threadId, int blockId, int textIndex, int* P, int* C, int* tweak0, int* Key1_0, int* Key1_1, int* Key1_2, int* Key1_3, int* Key2_0, int* Key2_1, int* Key2_2, int* Key2_3) {

	int i = threadId;
	int j = blockId;
	int threadIndex = i + 16 * j;//index of thread in a grid level.
	int plainTextIndex = textIndex;


	//XTS arrays
	__shared__ int binaryBlockId[16];
	__shared__ int tweak[16];
	__shared__ int aj[16]; // a to the power of j.
	__shared__ int T[16];

	aj[i] = 0;

	//First thread of each block converts the threadIndex in binary
	if (i == 0) {
		toBinaryArray(threadIndex, binaryBlockId);
	}
	__syncthreads;

	//First thread of each block calculates a^j
	if (i == 0) {
		int a[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0 };
		aj[14] = 1;
		for (int m = 0; m < j; m++) {
			product16(a, aj, aj);
		}
	}

	//Calculating tweak value. Tn = T0 + i
	tweak[i] = (tweak0[i] + binaryBlockId[i]) % 2;
	__syncthreads;

	///Key2 encrypts with tweak.
	SAESencrypt(i, i, tweak, Key2_0, Key2_1, Key2_2, Key2_3);

	//T = aj x E(key2,tweak)
	if (i == 0) {
		product16(tweak, aj, T);
	}
	__syncthreads;

	//CC = T xor Cj
	C[plainTextIndex] = (T[i] + C[plainTextIndex]) % 2;

	//PP = De(CC,Key1)
	SAESdecrypt(i, plainTextIndex, C, Key1_0, Key1_1, Key1_2, Key1_3);
	__syncthreads;

	//Pj = PP xor T
	P[plainTextIndex] = (T[i] + C[plainTextIndex]) % 2;

}

/*
* S-AES encryption device method when other kernels need to use SAES.
* Encrypts 16 bits in paralell. 
* i -  thread id in a block level from 0 to 16.
* plainTextIndex, the index that reads and writes from the plainText A.
*/
__device__ void SAESencrypt(int i, int plainTextIndex, int* A, int* K0, int* K1, int* K2, int* K3) {

	__shared__ 	int B[16];
	__shared__ int C[16];
	__shared__ int D[16];
	__shared__ int E[16];
	__shared__ int d1[4];
	__shared__ int d3[4];

	//PlainText XOR with K0
	B[i] = xOr(A[plainTextIndex], K0[i]);

	//Enter the rounds
	for (int round = 0; round < 3; round++) {

		//SBox substitution
		C[i] = getSBOXsubstitution(i, B);

		__syncthreads;
		//Shift Rows is applied directly

		//Mix Coloumns - only for the first two rounds
		if (round < 2) {

			//We Calculate D0,D1,D2,D3.
			if (i < 4) {
				D[i] = xOr(C[i], C[i + 12]); //D0 = C0+C3
			}
			else if (i < 8) {
				//Only one thread will calculate d1. Below we fill it in D1
				if (i == 4) {
					int twoHex[4] = { 0, 0, 1, 0 };
					int C0[4];
					int C3[4];
					sliceArray(C, 0, C0);
					sliceArray(C, 3, C3);
					int pr[4];
					product(twoHex, C3, pr);
					addition(C0, pr, d1);
				}
			}
			else if (i < 12) {
				D[i] = xOr(C[i], C[i - 4]); // D2 = C2 + C1
			}
			else {
				//Only one thread will calculate d3. Below we fill it in D3;
				if (i == 12) {
					int twoHex[4] = { 0, 0, 1, 0 };
					int C1[4];
					int C2[4];
					sliceArray(C, 2, C2);
					sliceArray(C, 1, C1);
					int pr[4];
					product(twoHex, C1, pr);
					addition(C2, pr, d3);
				}
			}
		}
		__syncthreads;
		//fill D1 and D3!
		if (i > 3 && i < 8) {
			D[i] = d1[i - 4];
		}
		else if (i > 11) {
			D[i] = d3[i - 12];
		}
		__syncthreads;

		//Add Round Key
		switch (round) {
		case 0: E[i] = xOr(D[i], K1[i]); break;
		case 1: E[i] = xOr(D[i], K2[i]); break;
		case 2:
			E[i] = xOr(C[i], K3[i]);

			//Because of the shifted rows of C
			if (i > 3 && i < 8) {
				E[i] = xOr(C[i + 8], K3[i]);
			}
			if (i > 11) {
				E[i] = xOr(C[i - 8], K3[i]);
			}
			break;
		}

		B[i] = E[i];
		//Wait all threads to start the next round
		__syncthreads;
	}
	A[plainTextIndex] = E[i];
}


/*
* S-AES decryption device method when other kernels need to use SAES.
* i -  thread id in a block level from 0 to 16.
* plainTextIndex, the index that reads and writes from the ciphertext A.
* Pass the shared int arrays B,C,D,E with 16 elements, which the threads use to communicate within the block.
* Pass shared int arrays d1,d3 with 4 elements.
*/
__device__ void SAESdecrypt(int i, int plainTextIndex, int* A, int* K0, int* K1, int* K2, int* K3) {

	__shared__ 	int B[16];
	__shared__ int C[16];
	__shared__ int D[16];
	__shared__ int T[16];
	__shared__ int d1[4];
	__shared__ int d3[4];

	//Enter inverse rounds
	for (int round = 0; round < 3; round++)
	{
		//Inverse Add Round Key
		switch (round) {
		case 0: B[i] = xOr(A[plainTextIndex], K3[i]); break;
		case 1: T[i] = xOr(C[i], K2[i]); break;
		case 2: T[i] = xOr(C[i], K1[i]); break;
		}
		__syncthreads;

		//Inverse Mix Coloumns  - for round last two rounds
		if (round > 0) {
			//Now only 4 threads will work, the others wait. i will take values 0,4,8,16;
			if (i % 4 == 0) {
				int x = i / 4;
				int result[4];
				int  F[4] = { 1, 1, 1, 1 };
				int  E[4] = { 1, 1, 1, 0 };
				int T0[4];
				int T1[4];
				int T2[4];
				int T3[4];

				if (x == 0) {
					sliceArray(T, 0, T0);
					int pr1[4];
					product(F, T0, pr1);

					sliceArray(T, 1, T1);
					int pr2[4];
					product(E, T1, pr2);

					addition(pr1, pr2, result);
				}
				else if (x == 1) {
					sliceArray(T, 0, T0);
					int pr1[4];
					product(E, T0, pr1);

					sliceArray(T, 1, T1);
					int pr2[4];
					product(E, T1, pr2);

					addition(pr1, pr2, result);

				}
				else if (x == 2) {
					sliceArray(T, 2, T2);
					int pr1[4];
					product(F, T2, pr1);

					sliceArray(T, 3, T3);
					int pr2[4];
					product(E, T3, pr2);

					addition(pr1, pr2, result);
				}

				else {
					sliceArray(T, 2, T2);
					int pr1[4];
					product(E, T2, pr1);

					sliceArray(T, 3, T3);
					int pr2[4];
					product(E, T3, pr2);

					addition(pr1, pr2, result);
				}

				//Fill
				for (int j = 0; j < 4; j++) {
					D[i + j] = result[j];
				}
			}
		}

		//Inverse Shift Rows
		// is implemented directly in the method getInvSBOXsubstitution

		//Inverse SBOX
		if (round == 0) {
			C[i] = getInvSBOXsubstitution(i, B);
		}
		else {
			C[i] = getInvSBOXsubstitution(i, D);
		}

		__syncthreads;
	}
	//Plain Text
	A[plainTextIndex] = xOr(C[i], K0[i]);
}


/*
* Returns the bit sbox subsitution based on the bit position.
*/
__device__ int getSBOXsubstitution(int bitID, int* B) {
	int bitGroup = bitID / 4; // A i takon B0, B1, B2, apo B3?
	int row = 2 * B[4 * bitGroup] + B[4 * bitGroup + 1]; //converting the 2 bit to decimal
	int column = 2 * B[4 * bitGroup + 2] + B[4 * bitGroup + 3];
	int* sboxValue = SBox[row][column]; ////sbox value i ka 4 elemente 
	return sboxValue[bitID % 4];
}

/*
* Returns the inverse bit sbox subsitution based on the bit position of the B matrix.
* Performs inverse shift rows. No need to shift rows before using this method!
*/
__device__ int getInvSBOXsubstitution(int bitID, int* B) {
	int bitGroup = bitID / 4; // does the bit belong to B0,B1,B2 or B3?

	//apply the InvShiftRows
	if (bitGroup == 1) {
		bitGroup = 3;
	}
	else if (bitGroup == 3) {
		bitGroup = 1;
	}

	int row = 2 * B[4 * bitGroup] + B[4 * bitGroup + 1]; //converting the 2 bit to decimal
	int column = 2 * B[4 * bitGroup + 2] + B[4 * bitGroup + 3];///converting the 2 bit to decimal
	int* sboxValue = invSBox[row][column]; //sbox value has 4 elements
	return sboxValue[bitID % 4];
}

/*
* Writes the Galois Field multiplication of two vectors of size 16 in reduced array.
* Uses 10011 as the irreducible polynomial.
*/
__device__ void product16(int* x, int* y, int* reduced) {
	int table[16][16] = { 0 };

	int result[31] = { 0 };//31 shifra mund te jete me se shumti prodhimi i dy numrave 16 bitesh (GF)// 16+(16-1)=31
	//Formojme tabelen 

	for (int i = 0; i < 16; i++)
	{
		for (int j = 0; j < 16; j++)
		{
			table[i][15 - j] = x[16 - 1 - j] * y[16 - 1 - i];
		}
	}

	//Llogarisim prodhimin , e pa reduktuar

	for (int n = 0; n < 31; n++) {
		if (n <= 15) {
			for (int k = 0; k <= n; k++) {
				result[n] = (result[n] + table[15 - n + k][k]) % 2;
			}
		}
		else {
			for (int k = 0; k < 31 - n; k++) {
				result[n] = (result[n] + table[k][n - 15 + k]) % 2;
			}
		}
	}
	//result[6] = table[0][3];
	//result[5] = (table[0][2] + table[1][3]) % 2;
	//result[4] = (table[0][1] + table[1][2] + table[2][3]) % 2;
	//result[3] = (table[0][0] + table[1][1] + table[2][2] + table[3][3]) % 2;
	//result[2] = (table[1][0] + table[2][1] + table[3][2]) % 2;
	//result[1] = (table[2][0] + table[3][1]) % 2;
	//result[0] = table[3][0];

	//Gjejme shkallen e polinomit
	int deegre = 31;
	int index = 0;
	for (int i = 0; i < 31; i++) {
		if (result[i] == 1) {
			index = i; //index at which the first element is 1 of the result
			break;
		}
		deegre -= 1;

	}
	int irreducible[17] = { 1,0,0,0,1,0,0,0,0,0,0,0,0,1,0,1,1 };

	//Nese shkalla ma e madhe se 4, atehere duhet ta reduktojme
	while (deegre > 16) {
		bool foundDegree = false;
		int index2 = 0;
		for (int i = index; i < 31; i++) {
			if (i < 17 + index) {
				result[i] = (irreducible[i - index] + result[i]) % 2;
			}
			else {
				result[i] = (result[i] + 0) % 2;
			}

			if (result[i] == 1 && !foundDegree) {
				index2 = i;
				foundDegree = true;
			}
		}


		index = index2;
		deegre = 31 - index2;
	}

	//Return an array with the last 16 bits 

	for (int i = 0; i < 16; i++) {
		reduced[i] = result[i + 15];
	}

}

/*
* Writes the xor addition of arrays x,y into rez
*/
__device__ void addition(int* x, int* y, int* rez) {
	for (int i = 0; i < 4; i++) {
		rez[i] = (x[i] + y[i]) % 2; //addition is XOR
	}
}

/*
* Writes the first 4 bits, or the second 4 bits, or the third 4 bits, or the last 4 bits of the 16 bit array in x array
*/
__device__  void sliceArray(int* arr, int part, int* x) {
	for (int i = 0; i < 4; i++)
	{
		x[i] = arr[4 * part + i];
	}
}

/*
* Converts number into a binary array
*/
__device__ void toBinaryArray(int num, int* binaryArray) {
	for (int i = 15; i >= 0; i--) {
		binaryArray[i] = num & 1;  // Extract the least significant bit
		num >>= 1;                // Shift right to get the next bit
	}
}


/*
* Writes the Galois Field multiplication of two vectors of size 4 in reduced array.
* Uses 10011 as the irreducible polynomial.
*/
__device__ void product(int* x, int* y, int* reduced) {
	int table[4][4] = { 0 };

	int result[7] = { 0 };//7 shifra mund te jete me se shumti prodhimi i dy numrave 4 bitesh (GF)// 4+(4-1)=7
	//Formojme tabelen 
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			table[i][3 - j] = x[4 - 1 - j] * y[4 - 1 - i];
		}
	}

	//Llogarisim prodhimin , e pa reduktuar

	//for (int n = 0; n < 7; n++) {
	//	if (n <= 3) {
	//		for (int k = 0; k <= n; k++) {
	//			result[n] = (result[n] + table[3 - n + k][k])%2;
	//		}
	//	}
	//	else {
	//		for (int k = 0; k <= 6-n; k++) {
	//			result[n] = (result[n] + table[k][n-3+k]) % 2;
	//		}
	//	}
	//}

	result[6] = table[0][3];
	result[5] = (table[0][2] + table[1][3]) % 2;
	result[4] = (table[0][1] + table[1][2] + table[2][3]) % 2;
	result[3] = (table[0][0] + table[1][1] + table[2][2] + table[3][3]) % 2;
	result[2] = (table[1][0] + table[2][1] + table[3][2]) % 2;
	result[1] = (table[2][0] + table[3][1]) % 2;
	result[0] = table[3][0];

	//Gjejme shkallen e polinomit
	int deegre = 7;
	int index = 0;
	for (int i = 0; i < 7; i++) {
		if (result[i] == 1) {
			index = i; //index at which the first element is 1 of the 
			break;
		}
		deegre -= 1;

	}
	int irreducible[5] = { 1,0,0,1,1 };

	//Nese shkalla ma e madhe se 4, atehere duhet ta reduktojme
	while (deegre > 4) {
		bool foundDegree = false;
		int index2 = 0;
		for (int i = index; i < 7; i++) {
			if (i < 5 + index) {
				result[i] = (irreducible[i - index] + result[i]) % 2;
			}
			else {
				result[i] = (result[i] + 0) % 2;
			}

			if (result[i] == 1 && !foundDegree) {
				index2 = i;
				foundDegree = true;
			}
		}
		index = index2;
		deegre = 7 - index2;
	}

	//Return an array with the last 4 bits 
	//reduced = new int[4]{ result[3], result[4], result[5], result[6] };

	reduced[0] = result[3];
	reduced[1] = result[4];
	reduced[2] = result[5];
	reduced[3] = result[6];

}


__device__   int xOr(int x, int y)
{
	return (x + y) % 2;
}

__device__ int and (int x, int y)
{
	return x * y;
}

