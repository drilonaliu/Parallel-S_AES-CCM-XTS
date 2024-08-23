#include "ParallelSAES.cuh"
#include "FileReader.h"
#include <iostream>
using namespace std;


int main() {

	ParallelSAES AES;

	//1. Encryption and decryption of a string
	string plainText = "Parallel Programming";
	string encrypted = AES.encrypt(plainText);
	string decrypted = AES.decrypt(encrypted);

	cout << "\n\nPlainText: "
		<< plainText
		<< "\n\nEncrypted: "
		<< encrypted
		<< "\n\nDecrypted: "
		<< decrypted
		<< "\n\n";

	//2. Encryption and decryption of a large txt file
	string plainTxt = readTextFile("Texts/PlainText_6.txt");
	string encryptedTxt = AES.encrypt(plainTxt);
	outputTextFile("Texts/Encrypted.txt", encryptedTxt);
	string decryptedTxt = AES.decrypt(encryptedTxt);
	outputTextFile("Tetxts/Decrypted.txt", decryptedTxt);

	return 0;
}
