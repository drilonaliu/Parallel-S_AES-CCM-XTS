#include <iostream>
#include "RoundKey.cuh"


int Sbox[4][4][4] = {
	 {{0, 1, 1, 0}, {1, 0, 1, 1}, {0, 0, 0, 0}, {0, 1, 0, 0}},
	 {{0, 1, 1, 1}, {1, 1, 1, 0}, {0, 0, 1, 0}, {1, 1, 1, 1}},
	 {{1, 0, 0, 1}, {1, 0, 0, 0}, {1, 0, 1, 0}, {1, 1, 0, 0}},
	 {{0, 0, 1, 1}, {0, 0, 0, 1}, {0, 1, 0, 1}, {1, 1, 0, 1}}
};

extern int* getRoundKey(int* key, int round) {
	int* newKey = new int[16] {0};
	int b[4] = { key[12],key[13],key[14],key[15] };
	int* g1 = g(b, round);
	for (int i = 0; i < 16; i++) {
		if (i < 4) {
			newKey[i] = (key[i] + g1[i]) % 2;
		}
		else {
			newKey[i] = (key[i] + newKey[i - 4]) % 2;
		}
	}
	return newKey;
}
int* g(int* b, int round) {
	int* result = new int[4] {0, 0, 0, 0};
	int* RC = rc(round);
	int* sboxValue = Sbox[2 * b[1] + b[2]][(2 * b[3] + b[0])];
	for (int i = 0; i < 4; i++) {
		result[i] = (sboxValue[i] + RC[i]) % 2;
	}
	delete[] RC;
	return result;
}

int* rc(int round) {
	if (round == 0) return new int[4] { 0, 0, 0, 1 };
	else if (round == 1)  return new int[4] { 0, 0, 1, 0 };
	else return new int[4] { 0, 1, 0, 0 };
}

int* xOr(int* a, int* b) {
	int* result = new int[4] {0};
	for (int i = 0; i < 4; i++) {
		result[i] = (a[i] + b[i]) % 2;
	}
	return result;
}