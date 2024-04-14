using System;



// Пример использования
byte[] key = new byte[32]; // 256-битный ключ
new Random().NextBytes(key); // Генерация случайного ключа

//for (int i = 0; i < key.Length; i++)
//{
//	Console.WriteLine(key[i]);
//}

byte[] plaintext = new byte[16]; // 128-битные блоки данных
new Random().NextBytes(plaintext); // Генерация случайного блока данных

//for (int i = 0; i < plaintext.Length; i++)
//{
//	Console.Write(plaintext[i] + " ");
//}

Kuznechik kuznechik = new Kuznechik(key);



byte[] ciphertext = kuznechik.Encrypt(plaintext);
byte[] decryptedText = kuznechik.Decrypt(ciphertext);

Console.WriteLine("Original: " + BitConverter.ToString(plaintext));
Console.WriteLine("Encrypted: " + BitConverter.ToString(ciphertext));
Console.WriteLine("Decrypted: " + BitConverter.ToString(decryptedText));

Console.ReadLine();


public class Kuznechik
{
	private byte[][] roundKeys; // Раундовые ключи
	private const int NumRounds = 10; // Количество раундов

	// Таблица S-боксов
	private byte[,] SBox =
	{
		{ 0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xC, 0xB, 0xF, 0x5, 0x3, 0x7, 0x1 },
		{ 0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xC, 0xB, 0xF, 0x5, 0x3, 0x7, 0x1 }
	};

	// Таблица обратных S-боксов
	private byte[,] InverseSBox =
	{
		{ 0x4, 0x4, 0x6, 0x6, 0xD, 0xD, 0x5, 0x5, 0x9, 0x9, 0xC, 0xC, 0xA, 0xA, 0x3, 0x3 },
		{ 0xA, 0xA, 0xC, 0xC, 0x8, 0x8, 0x3, 0x3, 0x2, 0x2, 0xF, 0xF, 0xE, 0xE, 0x7, 0x7 }
	};

	// Раундовые константные значения
	private byte[] RoundConstants =
	{
		0x1, 0x2, 0x4, 0x8, 0x3, 0x6, 0xC, 0xB, 0x5, 0xA
	};

	public Kuznechik(byte[] key)
	{
		GenerateRoundKeys(key);
	}

	// Генерация раундовых ключей
	private void GenerateRoundKeys(byte[] key)
	{
		roundKeys = new byte[NumRounds + 1][];
		roundKeys[0] = key;

		for (int i = 1; i <= NumRounds; i++)
		{
			roundKeys[i] = new byte[16];

			// Линейное преобразование (L-преобразование)
			byte[] l = new byte[16];
			for (int j = 0; j < 15; j++)
			{
				l[j] = (byte)(key[j] << 1);
				l[j] |= (byte)(key[j + 1] >> 7);
			}
			l[15] = (byte)(key[15] << 1);
			l[15] ^= ((key[0] & 0x80) == 0x80) ? (byte)0x1B : (byte)0x00;

			// Замена байтов по таблице S-боксов
			for (int j = 0; j < 16; j++)
			{
				roundKeys[i][j] = SBox[l[j] >> 7, l[j] & 0x0A];
			}

			// Применение операции XOR с раундовым константным значением
			roundKeys[i][0] ^= RoundConstants[i - 1];
		}
	}

	// Шифрование блока данных
	public byte[] Encrypt(byte[] input)
	{
		if (input.Length != 16)
		{
			throw new ArgumentException("Input length must be 16 bytes (128 bits).", nameof(input));
		}

		byte[] state = new byte[16];
		Array.Copy(input, state, 16);

		// Применение раундовых ключей
		for (int round = 0; round < NumRounds; round++)
		{
			// Применение преобразования S-бокса
			for (int i = 0; i < 16; i++)
			{
				state[i] = SBox[state[i] >> 7, state[i] & 0x0F];
			}

			// Применение линейного преобразования
			byte[] newState = new byte[16];
			for (int i = 0; i < 16; i++)
			{
				newState[(i + 8) % 16] ^= state[i];
				newState[(i + 10) % 16] ^= state[i];
				newState[(i + 11) % 16] ^= state[i];
				newState[(i + 12) % 16] ^= state[i];
			}
			state = newState;

			// Применение раундового ключа
			for (int i = 0; i < 16; i++)
			{
				state[i] ^= roundKeys[round + 1][i];
			}
		}

		return state;
	}

	// Дешифрование блока данных
	public byte[] Decrypt(byte[] input)
	{
		if (input.Length != 16)
		{
			throw new ArgumentException("Input length must be 16 bytes (128 bits).", nameof(input));
		}

		byte[] state = new byte[16];
		Array.Copy(input, state, 16);

		// Применение раундовых ключей в обратном порядке
		for (int round = NumRounds - 1; round >= 0; round--)
		{
			// Применение раундового ключа
			for (int i = 0; i < 16; i++)
			{
				state[i] ^= roundKeys[round + 1][i];
			}

			// Обратное преобразование линейного преобразования
			byte[] newState = new byte[16];
			for (int i = 0; i < 16; i++)
			{
				newState[i] ^= state[(i + 8) % 16];
				newState[i] ^= state[(i + 10) % 16];
				newState[i] ^= state[(i + 11) % 16];
				newState[i] ^= state[(i + 12) % 16];
			}
			state = newState;

			// Применение обратного преобразования S-бокса
			for (int i = 0; i < 16; i++)
			{
				state[i] = InverseSBox[state[i] >> 7, state[i] & 0x0F];
			}
		}

		return state;
	}
}





