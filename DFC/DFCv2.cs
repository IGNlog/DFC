using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.IO;

namespace DFC
{
    class DFCv2
    {
        /// <summary>
        /// Таблица с 32-битовыми константами 
        /// </summary>
        private static UInt32[] E={
        0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7,
        0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef,
        0x324e7738, 0x926cfbe5, 0xf4bf8d8d, 0x8c31d763,
        0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59584,

        0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
        0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf,
        0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4,
        0xc2b3293d, 0x20e9e5ea, 0xf02ac60a, 0xcc93ed87,

        0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0,
        0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
        0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3,
        0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe,

        0x393c48cb, 0xbbca060f, 0x0ff8ec6d, 0x31beb5cc,
        0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb,
        0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73,
        0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe67008e1,

        0x86d1bf27, 0x5b9b241d, 0xeb64749a, 0x47dfdfb9,
        0x6632c3eb, 0x061b6472, 0xbbf84c26, 0x144e49c2 };

        /// <summary>
        /// 32-битовые константы E[0...63]
        /// </summary>
        private static UInt32[] RT = {
        0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7,
        0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef,
        0x324e7738, 0x926cfbe5, 0xf4bf8d8d, 0x8c31d763,
        0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59584,
        0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
        0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf,
        0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4,
        0xc2b3293d, 0x20e9e5ea, 0xf02ac60a, 0xcc93ed87,
        0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0,
        0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
        0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3,
        0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe,
        0x393c48cb, 0xbbca060f, 0x0ff8ec6d, 0x31beb5cc,
        0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb,
        0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73,
        0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe67008e1};

        /// <summary>
        /// 64-битовая константа E[64]||E[65]
        /// </summary>
        private static UInt64 KD =  0x86d1bf275b9b241d;

        /// <summary>
        /// 32-битовая константа E[66]
        /// </summary>
        private static UInt32 KC= 0xeb64749a;

        /// <summary>
        /// 256-битовая константа
        /// </summary>
        private static UInt64[] KS = {
        0x86d1bf275b9b241d, 0xeb64749a47dfdfb9,
        0x6632c3eb061b6472, 0xbbf84c26144e49c2};

        /// <summary>
        /// (будет вычисляться при вызове конструктора)
        /// </summary>
        private static List<UInt64[]> KAB;

        /// <summary>
        /// Промежуточный результат шифрования (128 бит)
        /// </summary>
        private byte[] state = new byte[16];

        /// <summary>
        /// Непосредственно ключ
        /// </summary>
        private static UInt64[] key=new UInt64[2];

        /// <summary>
        /// Шифруемый текст
        /// </summary>
        public byte[] text;

        /// <summary>
        /// Раундовые подключи 
        /// </summary>
        public List<UInt64[]> RK;

        /// <summary>
        /// Конструктор
        /// </summary>
        public DFCv2(byte[] k)
        {
            KAB = new List<ulong[]>();
            for(int i=0; i<=15; i++)
            {
                UInt64 kab0 = E[4 * i], kab1 = E[4 * i+1], kab2 = E[4 * i+2], kab3 = E[4 * i+3];
                kab0 = kab0 << 32; kab2 = kab2 << 32;
                kab0 = kab0 ^ kab1; kab2 = kab2 ^ kab3;
                UInt64[] arr = { kab0, kab2 };
                KAB.Add(arr);
            }
            //Переводим байтовое представление ключа в ulong(для удобства работы)
            key = KeyCheckAndRebuild(k);
            RK=GenerationRoundKeys(key);
        }

        /// <summary>
        /// Подготока исходно текста к шифрованию
        /// </summary>
        /// <param name="sourceText">Исходный текст</param>
        /// <returns>Готовый к шифрованию текст</returns>
        public static byte[] TextPrepare(byte[] sourceText)
        {
            //Узнаём сколько нужно дописать в конец блока
            int lenghtZero = sourceText.Length % 16;
            byte[] buf = sourceText;
            if (lenghtZero > 0)
            {
                //Копируе все исходные байты в раширенный массив
                Array.Resize(ref buf, sourceText.Length + (16 - lenghtZero));
                buf[sourceText.Length] = 0x80;
                for (int i = 1; i < lenghtZero; i++)
                {
                    //остаток дополняем нулями 
                    buf[sourceText.Length + i] = 0x00;
                }
            }
            else//если длина текста кратна 16 дописываем целый блок
            {
                Array.Resize(ref buf, sourceText.Length + 16);
                buf[sourceText.Length] = 0x80;
                for (int i = 1; i < 16; i++)
                {
                    buf[sourceText.Length + i] = 0x00;
                }
            }
            return buf;
        }

        /// <summary>
        /// Проверка и укарачивание ключа
        /// </summary>
        /// <param name="k">Ключ</param>
        /// <returns>Обрезанный либо null, если произошла ошибка или ключ слишком короткий</returns>
        public static UInt64[] KeyCheckAndRebuild(byte[] k)
        {
            try
            {
                if (k.Length < 16)
                {
                    Console.WriteLine("Длина ключа меньше минимальной!\n" + "Попробуйте ввести другой ключ");
                    return null;
                }
                else
                {
                    UInt64[] keybuf = new UInt64[2];
                    keybuf[0] = keybuf[1] = 0;
                    for (int i = 0; i < 8; i++)
                    {

                        keybuf[0] <<= 8; keybuf[0] ^= k[i];
                        keybuf[1] <<= 8; keybuf[1] ^= k[i + 8];
                    }
                    return keybuf;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Раундовая функция 
        /// </summary>
        /// <param name="X"></param>
        /// <param name="K"></param>
        /// <returns></returns>
        private static UInt64 RF(UInt64 X, UInt64[] K)
        {
            BigInteger PowerTwo64 = new BigInteger(Math.Pow(2, 64));
            //UInt64 PowerTwo64 = (UInt64)Math.Pow(2, 64);
            UInt64 buf = (UInt64)((K[0] * X + K[1])%(PowerTwo64 + 13));
            buf = (UInt64)(buf % PowerTwo64);
            CP(buf);
            return buf;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="y"></param>
        /// <returns></returns>
        private static UInt64 CP(UInt64 y)
        {
            UInt64 buf=0;
            //UInt64 PowerTwo64 = (UInt64)Math.Pow(2, 64);
            BigInteger PowerTwo64 = new BigInteger(Math.Pow(2, 64));
            UInt32 yL=(UInt32)(y>>32), yR= (UInt32)(y);
            yR = yR ^ RT[trunc(yR)]; yL = yL ^ KC;
            buf = (UInt64)((((UInt64)yR ^ yL)+KD)% PowerTwo64);
            return buf;
        }

        /// <summary>
        /// Числовое значение которое определяется 6 левыми битами(старшими) блока данных
        /// </summary>
        /// <param name="yL">32-битовый блок</param>
        /// <returns>Индекс</returns>
        private static UInt32 trunc(UInt32 yL)
        {
            return yL >> 26;
        }

        /// <summary>
        /// Генерация раундовых ключей
        /// </summary>
        /// <param name="k">Ключ(главный)</param>
        /// <returns>Список раундовых ключей</returns>
        private static List<UInt64[]> GenerationRoundKeys(UInt64[] k)
        {
            UInt64[] arr = new UInt64[2], IRK0=new UInt64[2], RK0=new UInt64[2];
            List<UInt64[]> IRK = new List<UInt64[]>();
            for(int i=0;i<33;i++)
            {
                arr[0]=arr[1]=0;
                IRK.Add(arr);
            }
            UInt64[] PK = { key[0],key[1], KS[0],KS[1] };
            IRK0[0] = PK[0]; IRK0[1] = PK[1]; RK0[0] = PK[2]; RK0[1] = PK[3];
            IRK[0]=IRK0;

            int s = 0;
            for(int i=1; i<=15; i++)
            {
                s = (int)(RT[i] % 16);
                IRK[i][0] = IRK[i - 1][0] ^ KAB[s][0];
                IRK[i][1] = IRK[i - 1][1] ^ KAB[s][1];
            }

            List<UInt64[]> RoundKey = new List<ulong[]>();
            RoundKey.Add(RK0);
            for(int i=1; i<=8; i++)
            {
                UInt64 X= RoundKey[i-1][0], Y= RoundKey[i - 1][1];
                for(int j=1; j<=4; j++)
                {
                    Y = Y ^ RF(X, IRK[4 * (i - 1) + 1]);
                    UInt64 buf = X;
                    X = Y;
                    Y = buf;
                }
                arr[0] = Y; arr[1] = X;
                RoundKey.Add(arr);
            }
            return RoundKey;
        }

        /// <summary>
        /// Шифрование блока по раундовым подключам
        /// </summary>
        /// <param name="block">Шифруемый блок</param>
        /// <param name="round">Количество раундов(рекомендовано 8)</param>
        /// <param name="roundkeys">Раундовые ключи</param>
        /// <returns>Зашифрованный блок</returns>
        private UInt64[] EncryptBlock(UInt64[] block, List<UInt64[]> roundkeys, int round)
        {
            UInt64 X = block[0];//левая чатсть блока
            UInt64 Y = block[1];//правая часть блока 
            UInt64 tmp = 0;
            for (int i=1; i<=round;i++)
            {
                Y = Y ^ RF(X, RK[i]);
                //меняем местами X Y
                tmp = Y;
                Y = X;
                X = tmp;
            }
            UInt64[] CT = new UInt64[2];
            CT[0] = Y; CT[1] = X;
            return CT;
        }

        /// <summary>
        /// Расшифрование блока по раундовым подключам
        /// </summary>
        /// <param name="block">Блок данных</param>
        /// <param name="roundkeys">Раундовые ключи</param>
        /// <param name="round">Количество раундов</param>
        /// <returns>Расшифрованный блок</returns>
        private UInt64[] DecryptBlock(UInt64[] block, List<UInt64[]> roundkeys, int round)
        {
            UInt64 X = block[0];//левая чатсть блока
            UInt64 Y = block[1];//правая часть блока 
            UInt64 tmp = 0;
            for (int i = round; i >= 1; i--)
            {
                Y = Y ^ RF(X, RK[i]);
                //меняем местами X Y
                tmp = Y;
                Y = X;
                X = tmp;
            }
            UInt64[] CT = new UInt64[2];
            CT[0] = Y; CT[1] = X;
            return CT;
        }

        /// <summary>
        /// Зашифрование текста 
        /// </summary>
        /// <param name="txt">Шифруемый текст</param>
        /// <returns>Зашифрованный текст</returns>
        public byte[] EncryptText(byte[] txt)
        {
            byte[] buf = txt;
            if (txt == null || txt.Length == 0)
            {
                Console.WriteLine("Текст шифруемого сообщения отсутствует");
                return buf;
            }
            try
            {
                //Проверяем, нужно ли дописывать 0x00 в конец,
                //чтобы дополнить блок
                int lenghtZero = txt.Length % 16;
                if (lenghtZero > 0)
                {
                    Array.Resize(ref buf, txt.Length + (16 - lenghtZero));
                    buf[txt.Length] = 0x80;
                    for (int i = 1; i < 16 - lenghtZero; i++)
                    {
                        buf[txt.Length + i] = 0x00;
                    }
                }
                else//если длина текста кратна 16 дописываем целый блок
                {
                    Array.Resize(ref buf, txt.Length + 16);
                    buf[txt.Length] = 0x80;
                    for (int i = 1; i < 16; i++)
                    {
                        buf[txt.Length + i] = 0x00;
                    }
                }
                UInt64[] block = new UInt64[2];
                for (int i = 0; i < buf.Length; i = i + 16)
                {
                    block[0] = block[1] = 0;
                    for (int j = 0; j < 8; j++)
                    {
                        block[0] <<= 8; block[0] ^= buf[i + j];
                        block[1] <<= 8; block[1] ^= buf[i + j + 8];
                    }
                    block = EncryptBlock(block, RK, 8);
                    buf[i+7] = (byte)block[0]; buf[i+15] = (byte)block[1];
                    for (int j = 6; j >= 0; j--)
                    {
                        block[0] >>= 8; block[1] >>= 8;
                        buf[i + j] = (byte)block[0];
                        buf[i + j + 8] = (byte)block[1];
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return buf;
        }

        /// <summary>
        /// Расшифрование текста
        /// </summary>
        /// <param name="txt">Зашифрованный текст</param>
        /// <returns>Расшифрованный текст</returns>
        public byte[] DecryptText(byte[] txt)
        {
            byte[] buf =new byte [txt.Length];
            Array.Copy(txt, buf, txt.Length);
            if (txt == null || txt.Length == 0)
            {
                Console.WriteLine("Текст дешефруемого сообщения отсутствует");
                return buf;
            }
            try
            {
                UInt64[] block = new UInt64[2];
                for (int i = 0; i < buf.Length; i = i + 16)
                {
                    block[0] = block[1] = 0;
                    for (int j = 0; j < 8; j++)
                    {
                        block[0] <<= 8; block[0] ^= buf[i + j];
                        block[1] <<= 8; block[1] ^= buf[i + j + 8];
                    }
                    block = DecryptBlock(block, RK, 8);
                    buf[i+7] = (byte)block[0]; buf[i + 15] = (byte)block[1];
                    for (int j = 6; j >= 0; j--)
                    {
                        block[0] >>= 8; block[1] >>= 8;
                        buf[i + j] = (byte)block[0];
                        buf[i + j + 8] = (byte)block[1];
                    }
                }
                //"обламываем" лишний конец сообщения
                int k = buf.Length;
                while (buf[k - 1] != 0x80)
                {
                    k--;
                }
                Array.Resize(ref buf, k - 1);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return buf;
        }

        /// <summary>
        /// Бинарное чтение из файла
        /// </summary>
        /// <param name="fileName">Имя файла</param>
        /// <returns></returns>
        public byte[] ReadByteArrayFromFile(string fileName)
        {
            byte[] buf = null;

            try
            {
                FileStream file = new FileStream(fileName,
                    FileMode.Open, FileAccess.Read);
                BinaryReader binary = new BinaryReader(file);
                long numBytes = new FileInfo(fileName).Length;
                buf = binary.ReadBytes((int)numBytes);

                binary.Close();
                file.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return buf;
        }

        /// <summary>
        /// Бинарная запись в файл
        /// </summary>
        /// <param name="buf">Массив, который необходимо записать</param>
        /// <param name="fileName">Имя файла</param>
        public void WriteByteArrayToFile(byte[] buf, string fileName)
        {
            try
            {
                FileStream file = new FileStream(fileName,
                    FileMode.Create, FileAccess.ReadWrite);
                BinaryWriter binary = new BinaryWriter(file);

                for (int i = 0; i < buf.Length; i++)
                {
                    binary.Write(buf[i]);
                }

                binary.Close();
                file.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

    }
}
