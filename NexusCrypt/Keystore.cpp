#include "stdafx.h"
#include "Keystore.h"

#include "Keccak-more-compact.h"
#include "json/json.h"

using namespace boost;
using namespace boost::algorithm;
using namespace boost::property_tree;

const int ScryptN = 1 << 18;
const int ScryptP = 1;
const int ScryptR = 8;
const int ScryptDKLen = 32;

void SetData(std::map<std::string, std::string>& m, const std::string& name, const std::string& value)
{
	m.insert(std::make_pair(name, "S" + value));
}

void SetData(std::map<std::string, std::string>& m, const std::string& name, const int64_t value)
{
	m.insert(std::make_pair(name, "N" + std::to_string(value)));
}

void SetData(std::map<std::string, std::string>& m, const Json::Value& value)
{
	for each (auto& name in value.getMemberNames())
	{
		auto& data = value.get(name, "");
		if (data.isInt64())
			SetData(m, name, data.asInt64());
		else
			SetData(m, name, data.asString());
	}
}

void GetData(const std::map<std::string, std::string>& m, const std::string& name, std::string& value)
{
	auto pos = m.find(name);
	if (pos != m.end())
	{
		auto type = pos->second.at(0);
		if (type == 'S')
		{
			value = pos->second.substr(1);
			return;
		}
	}

	throw std::exception("잘못된 형식입니다");
}

void GetData(const std::map<std::string, std::string>& m, const std::string& name, int64_t& value)
{
	auto pos = m.find(name);
	if (pos != m.end())
	{
		auto type = pos->second.at(0);
		if (type == 'N')
		{
			value = strtol(pos->second.substr(1).c_str(), nullptr, 10);
			return;
		}			
	}

	throw std::exception("잘못된 형식입니다");
}

void GetData(const std::map<std::string, std::string>& m, Json::Value& value)
{
	for each (auto& pos in m)
	{
		auto type = pos.second.at(0);
		if (type == 'S')
			value[pos.first] = pos.second.substr(1);
		else if (type == 'N')
			value[pos.first] = strtol(pos.second.substr(1).c_str(), nullptr, 10);
		else
			throw std::exception("잘못된 형식입니다");
	}
}

Keystore LoadKeystore(const std::string& filepath)
{
	Keystore keystore;

	try
	{
		std::ifstream file(filepath);

		std::stringstream ss;		
		ss << file.rdbuf();
		auto content = ss.str();
		
		Json::Value root;
		Json::Reader reader;
		if (reader.parse(content.c_str(), root) == false)
			throw std::exception("JSON 형식이 아닙니다");

		keystore.version = root.get("version", 0).asInt();
		keystore.id = root.get("id", "").asString();
		keystore.address = root.get("address", "").asString();
		keystore.keytype = root.get("keytype", "").asString();

		{
			auto& crypto = root["crypto"];
			if (crypto.empty())
				crypto = root["Crypto"];

			keystore.crypto.cipher = crypto.get("cipher", "").asString();
			keystore.crypto.ciphertext = crypto.get("ciphertext", "").asString();			
			SetData(keystore.crypto.cipherparams, crypto["cipherparams"]);
			
			keystore.crypto.kdf = crypto.get("kdf", "").asString();
			SetData(keystore.crypto.kdfparams, crypto["kdfparams"]);

			keystore.crypto.mac = crypto.get("mac", "").asString();
		}
	}
	catch (const std::exception&)
	{
		throw std::exception("잘못된 파일형식입니다");
	}

	return keystore;
}

void SaveKeystore(const Keystore& keystore, const std::string& filepath)
{
	try
	{
		Json::Value root;
		
		root["version"] = keystore.version;
		root["id"] = keystore.id;
		root["address"] = keystore.address;

		if (keystore.keytype.empty() == false)
			root["keytype"] = keystore.keytype;

		{
			Json::Value crypto;
			crypto["cipher"] = keystore.crypto.cipher;
			crypto["ciphertext"] = keystore.crypto.ciphertext;
			GetData(keystore.crypto.cipherparams, crypto["cipherparams"]);

			crypto["kdf"] = keystore.crypto.kdf;
			GetData(keystore.crypto.kdfparams, crypto["kdfparams"]);

			crypto["mac"] = keystore.crypto.mac;

			root["crypto"] = crypto;
		}

		Json::StyledWriter writer;
		auto content = writer.write(root);

		std::ofstream file(filepath);

		file.write(content.c_str(), content.length());		
	}
	catch (const std::exception&)
	{
		throw std::exception("잘못된 파일형식입니다");
	}
}

std::vector<uint8_t> GetKDFKey(const Crypto& crypto, const std::string& auth)
{
	auto dklen = 0ll;
	auto n = 0ll;
	auto r = 0ll;
	auto p = 0ll;

	GetData(crypto.kdfparams, "dklen", dklen);
	GetData(crypto.kdfparams, "n", n);
	GetData(crypto.kdfparams, "r", r);
	GetData(crypto.kdfparams, "p", p);	
	std::string hexSalt;
	GetData(crypto.kdfparams, "salt", hexSalt);

	std::vector<uint8_t> salt;
	unhex(hexSalt, std::back_inserter(salt));

	std::vector<uint8_t> key(dklen);

	if (crypto.kdf == "scrypt")
	{
		if (EVP_PBE_scrypt(auth.c_str(), auth.length(), 
			&salt[0], salt.size(), n, r, p, 
			1024 * 1024 * 1024, // 1GB
			&key[0], key.size()) != 1)
			throw std::exception("scrypt 에러입니다");
	}
	else
		throw std::exception("지원하지 않는 키유도 함수입니다");

	return key;
}

std::vector<uint8_t> AES_CTR_XOR_Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv)
{
	std::vector<uint8_t> plaintext(ciphertext.size() + 32);
	auto result = false;

	auto ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		goto FINAL;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, &key[0], &iv[0]) != 1)
		goto FINAL;

	int len = 0;
	if (EVP_DecryptUpdate(ctx, &plaintext[0], &len, &ciphertext[0], ciphertext.size()) != 1)
		goto FINAL;

	int lenFinal = 0;
	if (EVP_DecryptFinal_ex(ctx, &plaintext[len], &lenFinal) != 1)
		goto FINAL;

	plaintext.resize(len + lenFinal);

	result = true;
FINAL:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if (result == false)
		throw std::exception("AES128-CTR Decrypt 에러입니다");

	return plaintext;
}

std::vector<uint8_t> AES_CTR_XOR_Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv)
{
	std::vector<uint8_t> ciphertext(plaintext.size() + 32);
	auto result = false;

	auto ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		goto FINAL;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, &key[0], &iv[0]) != 1)
		goto FINAL;

	int len = 0;
	if (EVP_EncryptUpdate(ctx, &ciphertext[0], &len, &plaintext[0], plaintext.size()) != 1)
		goto FINAL;

	int lenFinal = 0;
	if (EVP_DecryptFinal_ex(ctx, &ciphertext[len], &lenFinal) != 1)
		goto FINAL;

	ciphertext.resize(len + lenFinal);

	result = true;
FINAL:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if (result == false)
		throw std::exception("AES128-CTR Encrypt 에러입니다");

	return ciphertext;
}

Keyplain DecryptKeystore(const Keystore& keystore, const std::string& password)
{
	Keyplain keyplain;

	if (keystore.version == 3)
	{
		if (keystore.crypto.cipher != "aes-128-ctr")
			throw std::exception("지원하지 않는 암호화입니다");

		std::vector<uint8_t> mac;
		unhex(keystore.crypto.mac, std::back_inserter(mac));
			
		std::string hexIV;
		GetData(keystore.crypto.cipherparams, "iv", hexIV);
		std::vector<uint8_t> iv;
		unhex(hexIV, std::back_inserter(iv));

		std::vector<uint8_t> ciphertext;
		unhex(keystore.crypto.ciphertext, std::back_inserter(ciphertext));

		auto derivedKey = GetKDFKey(keystore.crypto, password);

		std::vector<uint8_t> unhashedMAC;
		unhashedMAC.insert(unhashedMAC.end(), derivedKey.begin() + 16, derivedKey.end());
		unhashedMAC.insert(unhashedMAC.end(), ciphertext.begin(), ciphertext.end());

		std::vector<uint8_t> calcuatedMAC(32);
		Sha3::Keccak256(&unhashedMAC[0], unhashedMAC.size(), &calcuatedMAC[0]);

		if (calcuatedMAC != mac)
			throw std::exception("비밀번호가 다릅니다");

		auto plaintext = AES_CTR_XOR_Decrypt(
			std::vector<uint8_t>(derivedKey.begin(), derivedKey.begin() + 16), 
			ciphertext, iv);

		keyplain.version = keystore.version;
		keyplain.id = keystore.id;
		keyplain.address = keystore.address;
		keyplain.keytype = keystore.keytype;

		if (keyplain.keytype.empty())
			hex(plaintext, std::back_inserter(keyplain.key));
		else
			keyplain.key.assign(plaintext.begin(), plaintext.end());
	}
	else
		throw std::exception("지원하지 않는 버전입니다");

	return keyplain;
}

Keystore EncryptKeyplain(const Keyplain& keyplain, const std::string& password)
{
	Keystore keystore;

	keystore.version = 3;
	keystore.address = keyplain.address;
	keystore.id = keyplain.id;
	keystore.keytype = keyplain.keytype;

	std::vector<uint8_t> salt(32);
	RAND_bytes(&salt[0], salt.size());

	std::vector<uint8_t> derivedKey(ScryptDKLen);
	if (EVP_PBE_scrypt(password.c_str(), password.length(), 
		&salt[0], salt.size(), ScryptN, ScryptR, ScryptP, 
		1024 * 1024 * 1024, // 1GB
		&derivedKey[0], derivedKey.size()) != 1)
		throw std::exception("scrypt 에러입니다");

	std::vector<uint8_t> key;
	if (keyplain.keytype.empty())
		unhex(keyplain.key, std::back_inserter(key));
	else
		key.assign(keyplain.key.begin(), keyplain.key.end());

	std::vector<uint8_t> iv(16);
	RAND_bytes(&iv[0], iv.size());

	auto ciphertext = AES_CTR_XOR_Encrypt(
		std::vector<uint8_t>(derivedKey.begin(), derivedKey.begin() + 16), 
		key, iv);

	std::vector<uint8_t> unhashedMAC;
	unhashedMAC.insert(unhashedMAC.end(), derivedKey.begin() + 16, derivedKey.end());
	unhashedMAC.insert(unhashedMAC.end(), ciphertext.begin(), ciphertext.end());

	std::vector<uint8_t> mac(32);
	Sha3::Keccak256(&unhashedMAC[0], unhashedMAC.size(), &mac[0]);

	keystore.crypto.kdf = "scrypt";
	SetData(keystore.crypto.kdfparams, "dklen", ScryptDKLen);
	SetData(keystore.crypto.kdfparams, "n", ScryptN);
	SetData(keystore.crypto.kdfparams, "r", ScryptR);
	SetData(keystore.crypto.kdfparams, "p", ScryptP);	
	std::string hexSalt;
	hex(salt, std::back_inserter(hexSalt));
	SetData(keystore.crypto.kdfparams, "salt", hexSalt);

	keystore.crypto.cipher = "aes-128-ctr";
	hex(ciphertext, std::back_inserter(keystore.crypto.ciphertext));
	std::string hexIV;
	hex(iv, std::back_inserter(hexIV));
	SetData(keystore.crypto.cipherparams, "iv", hexIV);

	hex(mac, std::back_inserter(keystore.crypto.mac));

	return keystore;
}