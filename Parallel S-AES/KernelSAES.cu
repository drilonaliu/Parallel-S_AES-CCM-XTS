#include "KernelSAES.cuh";
#include <iostream>
//#include "device_launch_parameters.h"

//for __syncthreads()
#ifndef __CUDACC__ 
#define __CUDACC__
#endif
#include <device_functions.h>

/*
*
* Each thread takes care of the encryption of each bit. Launch 16 threads to encrypt the 16 bits in parallel.
* @A - Plain Text
* @K0 - key in round 0
* @K1 - key in round 1
* @K2 - key in round 2
* @K3 - key in round 3
*
* All of the parametres should be passed as an integer array with 16 elements.
*
*/
__global__ void cudaEncrypt(int* A, int* K0, int* K1, int* K2, int* K3) {

	__shared__ 	int B[16];
	__shared__ int C[16];
	__shared__ int D[16];
	__shared__ int E[16];
	__shared__ int d1[4]; //mix coloumns D1
	__shared__ int d3[4]; //mix coloumns D3

	int i = threadIdx.x;
	int plainTextIndex = i + 16 * blockIdx.x;

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


/* Decrypts 16 bits in parallel using the Simplified AES scheme.
*
* Each thread takes care of the encryption of each bit. Launch 16 threads to encrypt the 16 bits in parallel.
* @A - Encrypted Bits
* @K0 - key in round 0
* @K1 - key in round 1
* @K2 - key in round 2
* @K3 - key in round 3
*
* All of the parametres should be passed as  integer arrays with 16 elements.
*
*/
__global__ void cudaDecrypt(int* A, int* K0, int* K1, int* K2, int* K3) {
	int i = threadIdx.x;
	int plainTextIndex = i + 16 * blockIdx.x;

	__shared__ int B[16];
	__shared__ int C[16];
	__shared__ int D[16];
	__shared__ int T[16];
	__shared__ int P[16];


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
	P[i] = xOr(C[i], K0[i]);

	//Copy results back
	A[plainTextIndex] = P[i];
}


/*
* Returns the bit sbox subsitution based on the bit position.
*
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
* Writes the Galois Field multiplication of two vectors of size 4 in reduced array.
* Uses 10011 as the irreducible polynomial.
*/
__device__ void product(int* x, int* y, int* reduced) {
	int table[4][4] = { 0 };
	//int* result = new int[7] { 0 }; //7 shifra mund te jete me se shumti prodhimi i dy numrave 4 bitesh (GF)// 4+(4-1)=7

	int result[7] = { 0 };
	//Formojme tabelen 
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			table[i][3 - j] = x[4 - 1 - j] * y[4 - 1 - i];
		}
	}

	//Llogarisim prodhimin , e pa reduktuar
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

	delete[] result;
	delete[] table;
}


__device__ int* reduce(int* x) {

	return x;
}

__device__   int xOr(int x, int y)
{
	return (x + y) % 2;
}

__device__ int and (int x, int y)
{
	return x * y;
}

