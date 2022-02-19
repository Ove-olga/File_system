#include <iostream>
#include <fstream>
#include <windows.h>
#include <wincrypt.h>
#include <time.h> 

#define PATH "Students.txt"
#pragma comment(lib, "crypt32.lib") 

using namespace std;

struct Sub {
	char* item = new char[21]();
	int* mark = new int(0);
};

class Mystr {
private:
	char* data = nullptr;

public:
	Mystr(const char in[]) {
		data = new char[strlen(in) + 1]();
		for (int i = 0; i < strlen(in); i++) {
			*(data + i) = in[i];
		}
		data[strlen(data)] = '\0';
	}

	~Mystr() {
		delete[] data;
	}

	void operator += (const char other[]) {
		char* temp = new char[strlen(data) + strlen(other) + 1]();
		int i = 0;
		for (; i < strlen(data); i++) {
			*(temp + i) = *(data + i);
		}
		for (int j = 0; j < strlen(other); j++) {
			*(temp + i + j) = *(other + j);
		}
		temp[strlen(temp)] = '\0';

		delete[] data;

		data = new char[strlen(temp) + 1]();
		for (i = 0; i < strlen(temp); i++) {
			*(data + i) = *(temp + i);
		}
		data[strlen(data)] = '\0';
	}
	char* Get() {
		return data;
	}
};

class Crypto {
private:
	char* Gen_pass() {
		srand(time(NULL));
		char* pass = new char[17];
		for (int i = 0; i < 16; ++i)
		{
			switch (rand() % 3) {
			case 0:
				pass[i] = rand() % 10 + '0';
				break;
			case 1:
				pass[i] = rand() % 26 + 'A';
				break;
			case 2:
				pass[i] = rand() % 26 + 'a';
			}
		}
		pass[16] = '\0';

		return pass;
	}

public:
	void Encrypt() {
		Mystr PATH_ENC(PATH);
		PATH_ENC += ".enc";

		ifstream File;
		File.open(PATH, ios::binary);
		ofstream File_enc;
		File_enc.open(PATH_ENC.Get(), ios::binary | ios::app);
		File_enc.seekp(0, ios::beg);

		int length;
		File.seekg(0, ios::end);
		length = File.tellg();
		File.seekg(0, ios::beg);

		char* szPassword = Gen_pass();

		int dwLength = strlen(szPassword);
		File_enc.write((char*)&dwLength, sizeof(dwLength));
		File_enc.write((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_len = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_len;
		DWORD dwBufferLen = 0;

		if (enc_len > 1)
		{
			dwBufferLen = dwBlockLen + enc_len;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = 0;
		bool final = false;

		while (count != length) {
			if (length - count < dwBlockLen) {
				dwBlockLen = length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBufferLen]();
			File.read((char*)temp, dwBlockLen);

			if (!CryptEncrypt(hKey, NULL, final, 0, temp, &dwBlockLen, dwBufferLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File_enc.write((char*)temp, dwBlockLen);

			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();

		if (remove(PATH) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}

	void Decrypt() {
		Mystr PATH_ENC(PATH);
		PATH_ENC += ".enc";

		ofstream File;
		File.open(PATH, ios::binary | ios::app);
		ifstream File_enc;
		File_enc.open(PATH_ENC.Get(), ios::binary);

		int length;
		File_enc.seekg(0, ios::end);
		length = File_enc.tellg();
		File_enc.seekg(0, ios::beg);

		if (length == -1 || length == 0) {
			return;
		}

		int dwLength;
		File_enc.read((char*)&dwLength, sizeof(dwLength));
		char* szPassword = new char[dwLength];
		File_enc.read((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_len = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_len;
		DWORD dwBufferLen = 0;

		if (enc_len > 1)
		{
			dwBufferLen = dwBlockLen + enc_len;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = sizeof(dwLength) + strlen(szPassword) + 1;
		bool final = false;

		while (count != length) {
			if (length - count < dwBlockLen) {
				dwBlockLen = length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBlockLen];
			File_enc.read((char*)temp, dwBlockLen);

			if (!CryptDecrypt(hKey, 0, final, 0, temp, &dwBlockLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File.write((char*)temp, dwBlockLen);
			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();
		if (remove(PATH_ENC.Get()) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}
};

class Program {
public:
	virtual void studentsPrinter(int val) = 0;

	void print(char* val) {
		cout << val;
	}

	void print(int val) {
		cout << val;
	}

	void print(const char val[]) {
		cout << val;
	}

	void cin_cl() {
		cin.seekg(0, ios::end);
		cin.clear();
	}

	bool checkLetters(char* line, int n) {
		int i = 0;
		int x = 1;
		while (line[i] != '\0') {
			if (!((line[i] >= 'а' && line[i] <= 'я') || (line[i] >= 'А' && line[i] <= 'Я'))) {
				x = 0;
				break;
			}
			i++;
		}
		if (x == 0) {
			return false;
		}
		else {
			return true;
		}
	}

	void protect_inp_ch(char* in, int len) {
		char* buf = new char[len + 1]();
		cin.get(buf, len + 1);
		cin_cl();
		bool flag = false;
		int count = 0;
		int k = 0;
		while ((*(buf + k)) != '\0') {
			count++;
			if (count >= len) {
				k = 0;
				count = 0;
				flag = false;
				print("Вы ввели недопустимое количество символов. Повторите ввод.\n");
				cin_cl();
				cin.get(buf, len + 1);
				cin_cl();
				continue;
			}
			else {
				flag = true;
			}
			k++;
		}
		cin_cl();
		if (strlen(buf) == 0) {
			print("Вы ввели пустую строку! Повторите ввод:\n");
			protect_inp_ch(in, len);
		}
		if (flag) {
			for (int i = 0; i < len; i++) {
				in[i] = *(buf + i);
			}
			delete[] buf;
		}
	}

	void Wait() {
		char temp[2];
		print("Нажмите [Enter] для продолжения.");
		cin_cl();
		cin.get(temp, 2);
		cin_cl();
	}
};

class Student : Program {
	friend class File;
public:
	Student() {
		surName = new char[31]();
		name = new char[31]();
		middleName = new char[31]();
		day = new int(0);
		month = new int(0);
		year = new int(0);
		startYear = new int(0);
		sex = new char[2]();
		faculty = new char[25]();
		department = new char[25]();
		group = new char[11]();
		recordCardNumber = new char[21]();
	}

	~Student() {
		delete surName;
		delete name;
		delete middleName;
		delete day;
		delete month;
		delete year;
		delete startYear;
		delete faculty;
		delete department;
		delete group;
		delete recordCardNumber;
	}

	void Set() {
		print("Фамилия: ");
		Set(surName, 31);
		if (!strcmp(surName, "-1")) {
			return;
		}
		while (!(checkLetters(surName, 31))) {
			print("Ожидался ввод русских букв. Повторите ввод: ");
			Set(surName, 31);
		}

		print("Имя: ");
		Set(name, 31);
		while (!(checkLetters(name, 31))) {
			print("Ожидался ввод русских букв. Повторите ввод: ");
			Set(name, 31);
		}

		print("Отчество: ");
		Set(middleName, 31);
		while (!(checkLetters(middleName, 31))) {
			print("Ожидался ввод русских букв. Повторите ввод: ");
			Set(middleName, 31);
		}

		print("Дата рождения [дд/мм/гггг]: ");
		while (!set_bd()) {
			print("Дата Рождения [дд/мм/гггг]: ");
		};

		print("Год поступления [1915-2021]: ");
		Set_startYear();

		print("Пол [М/Ж]: ");
		*sex = check_sex();
		*(sex + 1) = '\0';

		print("Факультет: ");
		Set(faculty, 25);
		while (!(checkLetters(faculty, 25))) {
			print("Ожидался ввод русских букв. Повторите ввод: ");
			Set(faculty, 25);
		}

		print("Кафедра: ");
		Set(department, 25);

		print("Группа: ");
		Set(group, 11);

		print("Номер зачетной книжки: ");
		protect_inp_ch(recordCardNumber, 21);
		cin_cl();
		while (!Check_recordCardNumber()) {
			print("Такой номер зачетной книжки уже существует. Повторите ввод: ");
			protect_inp_ch(recordCardNumber, 21);
			cin_cl();
		}
	}

	bool Edit() {
		int ans;
		cin >> ans;
		cin_cl();
		switch (ans) {
		case 1:
			print("Фамилия: ");
			Set(surName, 31);
			while (!(checkLetters(surName, 31))) {
				print("Ожидался ввод русских букв. Повторите ввод: ");
				Set(surName, 31);
			}
			break;
		case 2:
			print("Имя: ");
			Set(name, 31);
			while (!(checkLetters(name, 31))) {
				print("Ожидался ввод русских букв. Повторите ввод: ");
				Set(name, 31);
			}
			break;
		case 3:
			print("Отчество: ");
			Set(middleName, 31);
			while (!(checkLetters(middleName, 31))) {
				print("Ожидался ввод русских букв. Повторите ввод: ");
				Set(middleName, 31);
			}
			break;
		case 4:
			print("Дата Рождения [дд/мм/гггг]: ");
			while (!set_bd()) {
				print("Дата Рождения [дд/мм/гггг]: ");
			};
			break;
		case 5:
			print("Год Поступления [1980-2021]: ");
			Set_startYear();
			break;
		case 6:
			print("Пол [М/Ж]: ");
			*sex = check_sex();
			*(sex + 1) = '\0';
			break;
		case 7:
			print("Факультет: ");
			Set(faculty, 25);
			while (!(checkLetters(faculty, 25))) {
				print("Ожидался ввод русских букв. Повторите ввод: ");
				Set(faculty, 25);
			}
			break;
		case 8:
			print("Кафедра: ");
			Set(department, 25);
			break;
		case 9:
			print("Группа: ");
			Set(group, 11);
			break;
		case 10:
			print("Номер зачетной книжки: ");
			protect_inp_ch(recordCardNumber, 21);
			cin_cl();
			while (!Check_recordCardNumber()) {
				print("Такой номер зачетной книжки уже существует. Повторите ввод: ");
				protect_inp_ch(recordCardNumber, 21);
				cin_cl();
			}
			break;
		case 11: return true;
		default: {
			print("Введен неверный вариант\n");
			Edit();
		}
		}
		return false;
	}

private:
	char* surName = nullptr;
	char* name = nullptr;
	char* middleName = nullptr;
	int* day = nullptr;
	int* month = nullptr;
	int* year = nullptr;
	int* startYear = nullptr;
	char* sex = nullptr;
	char* faculty = nullptr;
	char* department = nullptr;
	char* group = nullptr;
	char* recordCardNumber = nullptr;

	void studentsPrinter(int val) override {
		return;
	}

	void Set(char* in, int len) {
		protect_inp_ch(in, len);
		cin_cl();
	}

	bool set_bd() {
		char* temp = new char[11]();
		*day = 0;
		*month = 0;
		*year = 0;
		cin.get(temp, 11);
		cin_cl();
		for (int i = 0; *(temp + i) != '\0'; i++) {
			if (*(temp + i) >= 48 && *(temp + i) <= 57 && ((i >= 0 && i <= 1) || (i >= 3 && i <= 4) || (i >= 6 && i <= 9))) {
				switch (i) {
				case 0: case 1:
					*day = *day * 10 + *(temp + i) - 0x30;
					break;
				case 3: case 4:
					*month = *month * 10 + *(temp + i) - 0x30;
					break;
				case 6: case 7: case 8: case 9:
					*year = *year * 10 + *(temp + i) - 0x30;
					break;
				}
			}
		}
		delete[] temp;
		if (check_date(*day, *month, *year)) return true;
		else return false;
	}

	void Set_startYear() {
		cin >> *startYear;
		while (*startYear < *year || *startYear - *year < 15 || *startYear < 1915 || *startYear > 2021) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				print("Ошибка! Некорректно введен Год Поступления.\n Повторите попытку [1915-2021]: ");
				cin >> *startYear;
				continue;
			}
			if (*startYear < *year || *startYear - *year < 15 || *startYear < 1915 || *startYear > 2021) {
				print("Ошибка! Некорректно введен Год Поступления.\n Повторите попытку [1915-2021]: ");
				cin.ignore(32767, '\n');
				cin >> *startYear;
			}
		}
		cin_cl();
	}

	bool Check_recordCardNumber() {
		int* len = new int(0);
		int* len_file = new int(0);
		char* buf = new char[21];
		Crypto crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(PATH, ios::binary);

		File.seekg(0, ios::end);
		*len_file = File.tellg();
		File.seekg(0, ios::beg);

		while (*len != *len_file) {
			File.seekg(171, ios::cur);
			File.read(buf, 21);

			if (!strcmp(buf, recordCardNumber)) {
				File.close();
				crypt.Encrypt();
				return false;
			}

			int* session_count = new int(0);
			int* subject_count = new int(0);
			int* sum = new int(0);

			File.read((char*)&*session_count, 4);


			for (int i = 0; i < *session_count; i++) {
				File.read((char*)subject_count, 4);
				*sum += *subject_count;
			}
			File.seekg((*sum) * 25, ios::cur);


			*len += 196;
			*len = *len + *session_count * 4;
			*len = *len + (*sum) * 25;
		}
		File.close();
		crypt.Encrypt();
		return true;

	}

	bool check_date(int day, int month, int year) {
		if (day != 0 && month != 0 && year != 0) {
			if (year >= 1900 && year <= 2005) {
				if (month >= 1 && month <= 12) {
					switch (month) {
					case 1: case 3: case 5: case 7: case 8: case 10: case 12:
						if (day >= 1 && day <= 31) {
							return true;
						}
						break;
					case 2:
						if (year % 4 != 0 || year % 100 == 0 && year % 400 != 0) {
							if (day >= 1 && day <= 28) {
								return true;
							}
						}
						else {
							if (day >= 1 && day <= 29) {
								return true;
							}
						}
						break;
					case 4: case 6: case 9: case 11:
						if (day >= 1 && day <= 30) {
							return true;
						}
						break;
					default:
						print("Ошибка! Повторите ввод.\n");
						break;
					}
				}
				else {
					print("Ошибка! Месяц должен быть от 1 до 12\n");
				}
			}
			else {
				print("Ошибка! Год должен быть от 1900 до 2005\n");
			}
		}
		return false;
	}

	char check_sex() {
		char value;
		while (true) {
			cin >> value;
			if (value == 'М' || value == 'Ж' || value == 'ж' || value == 'м') {
				cin_cl();
				return value;
			}
			print("Ошибка! Вводите только буквы М(м)/Ж(ж) \n");
			cin_cl();
		}
	}
};

class Session : Program {
	friend class File;
public:
	Session() {
		session_count = new int(0);
		sub_count = nullptr;
	}

	~Session() {
		delete session_count;
		delete sub_count;
		delete subject;
	}

	void Set_session() {
		cout << "Количество семестров [1-9]: ";
		int value;
		cin >> value;
		while (value < 1 || value > 9) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				print("Ошибка! Повторите ввод [1-9]: ");
				cin >> value;
				continue;
			}
			if (value < 1 || value > 9) {
				print("Ошибка! Повторите ввод [1-9]: ");
				cin.ignore(32767, '\n');
				cin >> value;
			}
		}
		*session_count = value;

		sub_count = new int[*session_count];
		for (int i = 0; i < *session_count; i++) {
			cout << "Введите количество предметов в ";
			cout << i + 1;
			cout << "-м семестре [1-10]: ";
			int* buf = new int();
			cin >> *buf;
			while (*buf < 1 || *buf > 10) {
				if (cin.fail()) {
					cin.clear();
					cin.ignore(32767, '\n');
					print("Ошибка! Повторите ввод [1-10]: ");
					cin >> *buf;
					continue;
				}
				if (*buf < 1 || *buf > 10) {
					print("Ошибка! Повторите ввод [1-10]: ");
					cin.ignore(32767, '\n');
					cin >> *buf;
				}
			}
			*(sub_count + i) = *buf;
		}

		int* sum = new int(0);
		for (int i = 0; i < *session_count; i++) {
			*sum = *sum + *(sub_count + i);
		}
		subject = new Sub[*sum];
		int* session_num = new int(0);
		int* subject_num = new int(0);
		for (int i = 0; i < *sum; i++) {
			if (*subject_num >= sub_count[*session_num]) {
				(*session_num)++;
				*subject_num = 0;
			}
			(*subject_num)++;
			(subject + i)->item = new char[21]();
			(subject + i)->mark = new int(0);
			print("Укажите название ");
			print(*subject_num);
			print("-го предмета в ");
			print(*session_num + 1);
			print("-й сессии: ");
			protect_inp_ch((subject + i)->item, 21);
			cin_cl();
			print("Введите оценку за ");
			cout << (subject + i)->item;
			print(": ");
			int buf;
			while (true) {
				cin_cl();
				cin >> buf;
				cin_cl();
				if (buf >= 2 && buf <= 5) {
					*(subject + i)->mark = buf;
					break;
				}
				print("Неверные данные! Вводите значения от 2 до 5\n");
			}
		}
		delete sum;
		delete session_num;
		delete subject_num;
	}

	bool Edit_session() {
		int sub_sum = 0;
		for (int i = 0; i < *session_count; i++) {
			sub_sum = sub_sum + *(sub_count + i);
		}
		int pos = -1;
		Sub* temp = nullptr;
		int* temp_2 = nullptr;
		int sum = 0;
		int ans, num = -1, ses;
		cin >> ans;
		cin_cl();
		if (ans == 1) {
			if (*session_count < 9) {
				system("cls");
				int sub_new = 0;
				print("Введите количество предметов в новой сессии: ");
				cin >> sub_new;
				cin_cl();
				int sub_sum = 0;
				for (int i = 0; i < *session_count; i++) {
					sub_sum = sub_sum + *(sub_count + i);
				}

				temp = new Sub[sub_sum + sub_new]();
				*session_count = *session_count + 1;
				temp_2 = new int[*session_count]();

				for (int i = 0; i < sub_sum; i++) {
					for (int j = 0; j < 31; j++) {
						*((temp + i)->item + j) = *((subject + i)->item + j);
					}
					*((temp + i)->mark) = *((subject + i)->mark);
				}

				for (int i = sub_sum; i < sub_sum + sub_new; i++) {
					print("Введите название ");
					print(i - sub_sum + 1);
					print("-го предмета в новой сессии: ");
					protect_inp_ch((temp + i)->item, 21);
					print("Введите оценку за ");
					cout << (temp + i)->item;
					print(": ");
					int buf;
					while (true) {
						cin >> buf;
						cin_cl();
						if (buf >= 2 && buf <= 5) {
							*((temp + i)->mark) = buf;
							break;
						}
						print("Неверные данные! Вводите значения от 2 до 5\n");
					}
				}

				for (int i = 0; i < *session_count - 1; i++) {
					*(temp_2 + i) = *(sub_count + i);
				}

				*(temp_2 + *session_count - 1) = sub_new;

				delete[] subject;
				delete[] sub_count;

				*&subject = temp;
				*&sub_count = temp_2;
			}
			else {
				print("Достигнуто максимальное количество сессий\n");
				Wait();
			}
		}
		else if (ans == 2 || ans == 3 || ans == 4) {
			print("Введите номер сессии -----> ");
			cin >> ses;
			if (!(ses != 0 && ses <= *session_count)) {
				print("Номер такой сессии не найден, повторите ввод\n");
				Wait();
				return false;
			}
			ses -= 1;
			if (ans == 2 || ans == 4)
			{
				print("Введите номер предмета -----> ");
				cin >> num;
				if (!(num <= *(sub_count + ses) && num != 0)) {
					print("Номер такого предмета не найден, повторите ввод\n");
					Wait();
					return false;
				}
				num -= 1;
			}
			if (ans == 3) {
				if (*(sub_count + ses) == 10) {
					print("Достигнуто максимальное кол-во предметов\n");
					Wait();
					return false;
				}
				temp = new Sub[sub_sum + 1]();
			}
			else if (ans == 4) temp = new Sub[sub_sum + 1]();

			system("cls");
			int sum_new = 0;
			for (int i = 0; i < *session_count; i++) {
				for (int j = 0; j < *(sub_count + i); j++) {
					if (((!(ses == i && num == j) || ans != 4) && ans != 2) || (ans == 3 && num == -1)) {
						for (int k = 0; k < 21; k++) {
							*((temp + sum_new)->item + k) = *((subject + sum)->item + k);
						}
						*((temp + sum_new)->mark) = *((subject + sum)->mark);
						sum_new++;
					}

					else if (i == ses && j == num && ans == 2) {
						print("Выбранный предмет: ");
						cout << (subject + sum)->item << "\nОценка: " << *(subject + sum)->mark << "\n";
						print("\nЧто нужно изменить:\n\n[1] Название предмета\n[2] Оценку по предмету\n[3] Вернуться в блок редактирования\n");
						print("-----> ");
						int ans1;
						cin >> ans1;
						switch (ans1) {
						case 1:
							print("Введите название предмета: ");
							protect_inp_ch((subject + sum)->item, 21);
							break;
						case 2:
							print("Введите оценку: ");
							int buf;
							while (true) {
								cin_cl();
								cin >> buf;
								cin_cl();
								if (buf >= 2 && buf <= 5) {
									*(subject + sum)->mark = buf;
									break;
								}
								print("Неверные данные! Вводите значения от 2 до 5\n");
							}
							break;
						case 3:
							return false;
						}
					}
					if (ans == 3 && ses == i && j + 1 == *(sub_count + i)) {
						print("Введите название нового предмета: ");
						protect_inp_ch((temp + sum_new)->item, 21);
						cin_cl();
						print("Введите оценку за ");
						cout << (temp + sum_new)->item;
						print(": ");
						int buf;
						while (true) {
							cin_cl();
							cin >> buf;
							cin_cl();
							if (buf >= 2 && buf <= 5) {
								*(temp + sum_new)->mark = buf;
								break;
							}
							print("Неверные данные! Вводите значения от 2 до 5\n");
						}
						sum_new++;
					}
					sum++;
				}
			}

			if (ans == 4) {
				*(sub_count + ses) = *(sub_count + ses) - 1;
				if (*(sub_count + ses) == 0) {
					sum = 0;
					*session_count = *session_count - 1;
					int* temp_1 = new int[*session_count];
					for (int i = 0; i <= *session_count + 1; i++) {
						if (i != ses) {
							*(temp_1 + sum) = *(sub_count + i);
							sum++;
						}
					}
					delete[] sub_count;
					sub_count = temp_1;
				}
			}
			else if (ans == 3) {
				*(sub_count + ses) = *(sub_count + ses) + 1;
			}
			if (ans == 3 || ans == 4) {
				delete[] subject;
				subject = temp;
			}
		}
		else if (ans == 5) {
			return true;
		}
		else {
			print("Такого варианта не найдено\n");
			Wait();
			return false;
		}
		return false;
	}

private:
	int* session_count = nullptr;
	int* sub_count = nullptr;
	Sub* subject = nullptr;

	void studentsPrinter(int val) override {
		return;
	}

};

class File : Program {
public:
	Student* student_year = nullptr;
	File() {
		file_length = new int(0);
		len = new int(0);
		pos = new int(0);
		count = new int(0);
		sum = new int(0);
		rec_book_num = new char[21]();
	}

	~File() {
		delete file_length;
		delete count;
		delete sum;
	}

	void Add_student() {
		Student* student = new Student;
		Session* session = new Session;
		student->Set();
		if (!strcmp(student->surName, "-1")) {
			delete student;
			delete session;
			return;
		}
		session->Set_session();

		Crypto crypt;
		crypt.Decrypt();

		ofstream file(PATH, ios::binary | ios::app);

		file.write(student->surName, 31);
		file.write(student->name, 31);
		file.write(student->middleName, 31);
		file.write((char*)student->day, 4);
		file.write((char*)student->month, 4);
		file.write((char*)student->year, 4);
		file.write((char*)student->sex, 1);
		file.write((char*)student->startYear, 4);
		file.write(student->faculty, 25);
		file.write(student->department, 25);
		file.write(student->group, 11);
		file.write(student->recordCardNumber, 21);

		file.write((char*)session->session_count, 4);

		for (int i = 0; i < *session->session_count; i++) {
			file.write((char*)(&*(session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *session->session_count; i++) {
			*sum = *sum + *(session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			file.write((char*)(session->subject + i)->item, 21);
			file.write((char*)(session->subject + i)->mark, 4);
		}

		delete student;
		delete session;
		file.close();

		crypt.Encrypt();
	}

	void Edit_student() {
		ofstream test("Students.new.txt", ios::binary);
		test.close();
		Crypto crypt;
		int ans;
		int ans_2;
		if (!Stud_count()) return;
		system("cls");
		print("Редактирования информации о студенте\n\n");
		Print_students(1);
		while (!find_student()) {
			print("Такой студент не найден\n");
			print("1 - Ввести другой номер зачетной книжки\n");
			print("2 - Назад\n");
			print(">> ");
			cin >> ans_2;
			while (ans_2 != 1 && ans_2 != 2) {
				print("1 - Ввести другого студента\n");
				print("2 - Назад\n");
				print(">> ");
				cin >> ans_2;
			}
			if (ans_2 == 2) return;
		}
		if (*pos == -1) {
			return;
		}
		bool flag = true;
		while (flag) {
			print("1 - Редактировать сведения о студенте\n");
			print("2 - Редактировать данные о сессии студента\n");
			print("3 - Назад\n>> ");
			cin >> ans;
			len = new int(0);
			for (int i = 0; i < *count; i++) {
				Read_student();
				if (i != *pos) {
					Write_File();
				}
				else {
					switch (ans) {
					case 1:
						while (true) {
							system("cls");
							studentsPrinter(2);
							print("Редактирования информации о студенте\n");
							print("1 - Редактировать фамилию студента\n");
							print("2 - Редактировать имя студента\n");
							print("3 - Редактировать отчество студента\n");
							print("4 - Редактировать дату рождения студента\n");
							print("5 - Редактировать год приема студента в университет\n");
							print("6 - Редактировать пол студента\n");
							print("7 - Редактировать факультет студента\n");
							print("8 - Редактировать кафедру студента\n");
							print("9 - Редактировать группу студента\n");
							print("10 - Редактировать номер зачетной книжки студента\n");
							print("11 - Сохранить изменения\n");
							print(">> ");
							if (edit_student->Edit()) {
								break;
							}
						}
						break;
					case 2:
						while (true) {
							system("cls");
							print("Редактирования информации о сессии студента\n");
							studentsPrinter(1);
							studentsPrinter(3);
							print("1 - Добавить сессию\n");
							print("2 - Редактировать информацию о предметах студента\n");
							print("3 - Добавить предмет\n");
							print("4 - Удалить предмет\n");
							print("5 - Сохранить изменения\n");
							print(">> ");
							if (edit_session->Edit_session()) {
								break;
							};
						}
						break;
					case 3:
						flag = false;
						break;
					default:
						if (remove("Students.new.txt") != 0) {
							print("Ошибка при удалении файла!\n");
							Wait();
						}
						print("Такого варианта не найдено\n");
						Wait();
						break;
					}
					Write_File();
					delete edit_student;
					delete edit_session;
				}
			}
			if (remove("Students.txt.enc") != 0) {
				print("Ошибка при удалении файла!\n");
				Wait();
			}
			if (rename("Students.new.txt", PATH) != 0) {
				print("Ошибка при переименовании файла!\n");
				Wait();
			}
			crypt.Encrypt();
			delete len;
			flag = false;
		}
		delete pos;
		delete rec_book_num;
	}

	void Delete_student() {
		Crypto crypt;
		if (!Stud_count()) return;
		*pos = -1;
		rec_book_num = new char[21]();
		Print_students(1);
		print("Введите номер зачетной книжки (-1 чтобы вернуться назад) >> ");
		cin_cl();
		len = new int(0);
		protect_inp_ch(rec_book_num, 21);
		cin_cl();
		if (!strcmp(rec_book_num, "-1")) {
			return;
		}

		for (int i = 0; i < *count; i++) {
			Read_student();
			if (!strcmp(rec_book_num, edit_student->recordCardNumber)) {
				*pos = i;
				break;
			}
			delete edit_student;
			delete edit_session;
		}

		if (*pos != -1) {
			*len = 0;
			for (int i = 0; i < *count; i++) {
				Read_student();
				if (i != *pos) {
					Write_File();
				}
				delete edit_student;
				delete edit_session;
			}
			if (remove("Students.txt.enc") != 0) {
				print("Ошибка при удалении файла!\n");
				Wait();
			};
			if (rename("Students.new.txt", PATH) != 0) {
				print("Ошибка при переименовании файла!\n");
				Wait();
			}
			crypt.Encrypt();
		}
		else {
			print("Такой студент не найден\n");
			Delete_student();
		}

		delete pos;
		delete rec_book_num;
	}

	void Print_students(int rez) {
		if (!Stud_count()) return;
		len = new int(0);
		for (int i = 0; i < *count; i++) {
			Read_student();
			switch (rez) {
			case 1:
				studentsPrinter(1);
				break;
			case 2:
				studentsPrinter(2);
				break;
			case 3:
				studentsPrinter(1);
				studentsPrinter(3);
				break;
			case 4:
				studentsPrinter(2);
				studentsPrinter(3);
				break;
			}
			delete edit_student;
			delete edit_session;
		}
		delete len;
	}

	void Task() {
		if (!Stud_count()) return;
		int ans;
		int quantity;
		int* number = new int[9]();
		int sYear, eYear;
		float minBall = 5.0, maxBall = 0, buf = -1.0;
		print("Введите '1', чтобы осуществить поиск, иначе вернетесь в главное меню \n");
		print(">>>> ");
		cin >> ans;
		if (ans == 1) {
			while (true) {
				print("Введите количество семестров, в которых будет осуществляться поиск [1-9]: ");
				cin_cl();
				cin >> quantity;
				cin_cl();
				if (quantity >= 1 && quantity <= 9) {
					print("Введите ");
					cin_cl();
					cout << quantity;
					cin_cl();
					print(" номера семестров, в которых будет осуществляться поиск [1-9] ");
					for (int i = 0; i < quantity; i++) {
						while (true) {
							print(" >>>> ");
							cin >> *(number + i);
							cin_cl();
							if (*(number + i) > 0 && *(number + i) < 10) {
								*(number + i) = *(number + i) - 1;
								break;
							}
							print("Некорректно введен номер семестра. Повторите попытку [1-9]: \n");
						}
					}
					print("Введите интервал года рождения, в пределах которого будет осуществляться поиск{1900-2005}: \n");
					while (true) {
						print("Начальный год: ");
						cin >> sYear;
						cin_cl();
						print("Конечный год: ");
						cin >> eYear;
						cin_cl();
						if (!(sYear > 1899 && sYear < 2006 && eYear > 1899 && eYear < 2006 && sYear < eYear)) {
							print("Некорректно введен интервал года. Повторите попытку [1900-2005]: \n");
						}
						else break;
					}

					break;
				}
				print("Не верные данные! ");
			}
			len = new int(0);
			for (int i = 0; i < *count; i++)
			{
				Read_student();
				if (*edit_student->year >= sYear && *edit_student->year <= eYear) {
					buf = Sr_ball(quantity, number);
					if (buf != -1) {
						if (buf > maxBall) maxBall = buf;
						if (buf < minBall) minBall = buf;
					}
				}
			}

			if (minBall != 5 || maxBall != 0) {
				if (minBall == maxBall) {
					print("Минимальный и максимальный средний балл одинаковый: ");
					cout << maxBall << "\n";
					print("Студенты, у которых средний балл равен +- 0.2 от среднего: \n\n");
					*len = 0;
					for (int i = 0; i < *count; i++)
					{
						Read_student();
						if (*edit_student->year >= sYear && *edit_student->year <= eYear) {
							buf = Sr_ball(quantity, number);
							if (buf != -1) {
								if (buf > maxBall - 0.2) {
									studentsPrinter(2);
									studentsPrinter(3);
								}
							}
						}
					}
				}
				else {
					if (minBall != 5) {
						print("Студенты, у которых средний балл равен +- 0.2 от минимального среднего балла: ");
						cout << minBall << "\n\n";
						*len = 0;
						for (int i = 0; i < *count; i++)
						{

							Read_student();
							if (*edit_student->year >= sYear && *edit_student->year <= eYear) {
								buf = Sr_ball(quantity, number);
								if (buf != -1) {
									if (buf < minBall + 0.2) {
										studentsPrinter(2);
										studentsPrinter(3);
									}
								}
							}
						}
					}
					if (maxBall != 0) {
						print("Студенты, у которых средний балл равен +- 0.2 от максимального среднего балла: ");
						cout << maxBall << "\n\n";
						*len = 0;
						for (int i = 0; i < *count; i++)
						{

							Read_student();
							if (*edit_student->year >= sYear && *edit_student->year <= eYear) {
								buf = Sr_ball(quantity, number);
								if (buf != -1) {
									if (buf > maxBall - 0.2) {
										studentsPrinter(2);
										studentsPrinter(3);
									}
								}
							}
						}
					}
				}
			}
			else {
				print("Студентов по заданным критериям не найдено\n");
			}
		}
	}

	float Sr_ball(int quantity, int* number) {
		int sum = 0;
		float srSum = 0;
		for (int i = 0; i < quantity; i++) {
			if (*edit_session->session_count - 1 < number[i]) return -1;
		}

		for (int i = 0; i < quantity; i++) {
			sum += edit_session->sub_count[number[i]];
			for (int j = 0; j < edit_session->sub_count[number[i]]; j++)
			{
				srSum += *((edit_session->subject) + i + j)->mark;
			}
		}

		srSum = srSum / sum;
		return srSum;
	}

private:
	Student* edit_student = nullptr;
	Session* edit_session = nullptr;
	int* file_length;
	int* len;
	int* pos;
	int* count;
	int* sum;
	char* rec_book_num;

	bool find_student() {
		*pos = -1;
		len = new int(0);
		rec_book_num = new char[21]();
		print("Введите номер зачетной книжки (-1 чтобы вернуться обратно) >> ");
		cin_cl();
		protect_inp_ch(rec_book_num, 21);
		cin_cl();

		if (!strcmp(rec_book_num, "-1")) {
			return true;
		}

		for (int i = 0; i < *count; i++) {
			Read_student();
			if (!strcmp(rec_book_num, edit_student->recordCardNumber)) {
				*pos = i;
				delete edit_student;
				delete edit_session;
				delete len;
				return true;
			}
			delete edit_student;
			delete edit_session;
		}
		delete len;
		return false;
	}

	void Read_student() {
		Crypto crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(PATH, ios::binary);

		File.seekg(0, ios::end);
		*file_length = File.tellg();
		File.seekg(*len, ios::beg);
		if (*len != *file_length) {
			edit_student = new Student();
			edit_session = new Session();

			File.read(edit_student->surName, 31);
			File.read(edit_student->name, 31);
			File.read(edit_student->middleName, 31);
			File.read((char*)edit_student->day, 4);
			File.read((char*)edit_student->month, 4);
			File.read((char*)edit_student->year, 4);
			File.read(edit_student->sex, 1);
			File.read((char*)edit_student->startYear, 4);
			File.read(edit_student->faculty, 25);
			File.read(edit_student->department, 25);
			File.read(edit_student->group, 11);
			File.read(edit_student->recordCardNumber, 21);

			File.read((char*)edit_session->session_count, 4);

			edit_session->sub_count = new int[*edit_session->session_count];
			*sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				File.read((char*)(&*(edit_session->sub_count + i)), 4);
				*sum = *sum + *(edit_session->sub_count + i);
			}

			edit_session->subject = new Sub[*sum]();

			for (int i = 0; i < *sum; i++) {
				File.read((char*)(edit_session->subject + i)->item, 21);
				File.read((char*)(edit_session->subject + i)->mark, 4);
			}
			*len += 196;
			*len += *edit_session->session_count * 4;
			*len += *sum * 25;
		}
		File.close();
		crypt.Encrypt();
	}

	void Write_File() {
		char newname[] = "Students.new.txt";
		ofstream FILE_NEW;
		FILE_NEW.open(newname, ios::binary | ios::app);

		FILE_NEW.write(edit_student->surName, 31);
		FILE_NEW.write(edit_student->name, 31);
		FILE_NEW.write(edit_student->middleName, 31);
		FILE_NEW.write((char*)edit_student->day, 4);
		FILE_NEW.write((char*)edit_student->month, 4);
		FILE_NEW.write((char*)edit_student->year, 4);
		FILE_NEW.write((char*)edit_student->sex, 1);
		FILE_NEW.write((char*)edit_student->startYear, 4);
		FILE_NEW.write(edit_student->faculty, 25);
		FILE_NEW.write(edit_student->department, 25);
		FILE_NEW.write(edit_student->group, 11);
		FILE_NEW.write(edit_student->recordCardNumber, 21);

		FILE_NEW.write((char*)edit_session->session_count, 4);

		for (int i = 0; i < *edit_session->session_count; i++) {
			FILE_NEW.write((char*)(&*(edit_session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *edit_session->session_count; i++) {
			*sum = *sum + *(edit_session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			FILE_NEW.write((char*)(edit_session->subject + i)->item, 21);
			FILE_NEW.write((char*)(edit_session->subject + i)->mark, 4);
		}
		FILE_NEW.close();
	}

	bool Stud_count() {
		fstream file("Students.txt.enc", ios::binary | ios::in);
		file.seekg(0, ios::end);
		if (file.tellg() == -1 || file.tellg() == 0) {
			file.close();
			print("Файл пустой, доступна только функция добавления студентов\n");
			return false;
		}
		file.close();

		Crypto* crypt = new Crypto;
		crypt->Decrypt();
		ifstream File;
		File.open(PATH, ios::binary);

		*len = 0;
		*count = 0;
		File.seekg(0, ios::end);
		*file_length = File.tellg();
		File.seekg(0, ios::beg);

		while (*file_length != *len) {
			File.seekg(192, ios::cur);
			*len = *len + 192;

			int session_count = 0;
			int subject_count = 0;

			File.read((char*)&session_count, 4);
			*len = *len + 4;

			*len = *len + session_count * 4;
			*sum = 0;
			for (int i = 0; i < session_count; i++) {
				File.read((char*)&subject_count, 4);
				*sum = *sum + subject_count;
			}
			File.seekg((*sum * 25), ios::cur);
			*len = *len + (*sum * 25);
			(*count)++;
		}
		File.close();
		crypt->Encrypt();
		return true;
	}

	void studentsPrinter(int rez) override {
		switch (rez) {
		case 1:
			print("--------------------------------------------------------------------------------------------\n\nДАННЫЕ О СТУДЕНТЕ\n\n");
			cout << "ФИО: " << edit_student->surName << " " << edit_student->name << " " << edit_student->middleName << "\n";
			cout << "Номер зачетной книжки: " << edit_student->recordCardNumber << "\n\n";
			break;
		case 2:
			print("--------------------------------------------------------------------------------------------\n\nДАННЫЕ О СТУДЕНТЕ\n\n");
			cout << "ФИО: " << edit_student->surName << " " << edit_student->name << " " << edit_student->middleName << "\n";
			cout << "Дата рождения: " << *edit_student->day << "." << *edit_student->month << "." << *edit_student->year << " Год приема: " << *edit_student->startYear << "\n";
			cout << "Пол: " << edit_student->sex << " Факультет: " << edit_student->faculty << " Кафедра: " << edit_student->department << " Группа: " << edit_student->group << "\n";
			cout << "Номер зачетной книжки: " << edit_student->recordCardNumber << "\n\n";
			break;
		case 3:
			print("ОЦЕНКИ \n\n");
			int sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				cout << "Cессия " << i + 1 << "\n";
				for (int j = 0; j < *((edit_session->sub_count) + i); j++) {
					cout << j + 1 << "." << ((edit_session->subject) + sum)->item << " " << *(((edit_session->subject) + sum)->mark) << "\n";
					sum++;
				}
				cout << "\n";
			}
			break;
		}
	}
};

class Menu : Program {
public:
	Menu() {
		ans = new int;
		file = new File;
	}

	~Menu() {
		delete file;
		delete ans;
	}

	bool hub() {
		file = new File;
		system("cls");
		print("Выберите вариант\n");
		print("1 - Добавить студента\n");
		print("2 - Удалить студента\n");
		print("3 - Изменить данные студента\n");
		print("4 - Вывести всю базу студентов\n");
		print("5 - Вывести данные о студентах, которые успевают с наибольшим и наименьшим успехом\n");
		print("6 - Выйти из программы\n");
		print(" >>>> ");
		cin >> *ans;
		while (*ans < 1 || *ans>6) {
			if (cin.fail()) {
				cin.clear();
				cin.ignore(32767, '\n');
				print("Ошибка! Введите номер пункта меню, который хотите вывести\n-----> ");
				cin >> *ans;
				continue;
			}
			if (*ans < 1 || *ans>6) {
				print("Вы ввели число не из диапозона [1;6]\nПовторите ввод —---> ");
				cin.ignore(32767, '\n');
				cin >> *ans;
			}
		}
		cin_cl();
		switch (*ans) {
		case 1: {
			system("cls");
			print("Добавление нового студента (Введите -1, чтобы вернуться назад)\n");
			file->Add_student();
			Wait();
			break;
		}
		case 2: {
			system("cls");
			print("Удаление студента\n");
			file->Delete_student();
			Wait();
			break;
		}
		case 3: {
			file->Edit_student();
			Wait();
			break;
		}
		case 4: {
			system("cls");
			print("Вывод всех студентов\n");
			print("1 - Вывод всей информации\n");
			print("2 - Вывод части информации (без данных о сессии)\n");
			print("3 - Назад\n");
			print(">>> ");
			cin >> *ans;
			switch (*ans) {
			case 1:
				file->Print_students(4);
				Wait();
				break;
			case 2:
				file->Print_students(2);
				Wait();
				break;
			case 3:
				break;
			}
			break;
		}
		case 5:
			system("cls");
			print("Вывод данных о студентах, которые успевают с наибольшим и наименьшим успехом\n");
			file->Task();
			Wait();
			break;
		case 6:
			return false;
		}
		return true;
		delete file;
	}

private:
	File* file = nullptr;
	int* ans = nullptr;

	void studentsPrinter(int rez) override {
		return;
	}
};

int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	Menu* menu = new Menu();
	while (menu->hub());
	delete menu;
	return 0;
}