#include "ParallelSAES.cuh"
#include "FileReader.h"
#include <iostream>
using namespace std;

/*
*  
*/
int main() {

	ParallelSAES AES;

	//Plain Text
	string plainText = "Parallel Proggraming with XTS mode!";
	int plainTextLength = 0;

	//Encryption of the string
	int* cipher = AES.encryptXTS(plainText, plainTextLength);

	//Decryption 
	string decrypted = AES.decryptXTS(cipher, plainTextLength);

	cout << "\n\n Decrypted Text: "
		 << decrypted;
	return 0;

}
