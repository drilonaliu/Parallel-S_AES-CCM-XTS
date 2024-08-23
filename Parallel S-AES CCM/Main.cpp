#include "ParallelSAES.cuh"
#include "FileReader.h"
#include <iostream>
using namespace std;


/*
* 
*/
int main() {

	ParallelSAES AES;

	//Encryption and decryption of a string
	string plainText = "Parallel Programming";
	int cipherTextLength = 0;
	bool isValid = false;
	int* cipherCCM = AES.encryptCCM(plainText, cipherTextLength);
	string decrypted = AES.decryptCCM(cipherCCM, cipherTextLength, isValid);

	cout << "\nPlain Text: "
		<< plainText
		<< "\n\n Decrypted: "
		<< decrypted;

	//Are the tags same?
	if (isValid) {
		cout << "\n\nTags are the same!";
	}
	else {
		cout << "\n\nTags are not the same! Someone has modified the file.";
	}

	return 0;

}
