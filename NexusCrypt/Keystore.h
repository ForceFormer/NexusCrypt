#pragma once

struct Crypto
{
	std::string cipher;
	std::string ciphertext;
	std::map<std::string, std::string> cipherparams;
	std::string kdf;
	std::map<std::string, std::string> kdfparams;
	std::string mac;
};

struct Keystore
{
	int version;
	std::string id;
	std::string address;
	std::string keytype;
	Crypto crypto;
};

struct Keyplain
{
	int version;
	std::string id;
	std::string address;
	std::string keytype;
	std::string key;
};

Keystore LoadKeystore(const std::string& filepath);
void SaveKeystore(const Keystore& keystore, const std::string& filepath);
Keyplain DecryptKeystore(const Keystore& keystore, const std::string& password);
Keystore EncryptKeyplain(const Keyplain& keyplain, const std::string& password);