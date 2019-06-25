using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace DFC
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Введите ключ: ");
            string strKey = Console.ReadLine();
            byte[] byteKey = Encoding.UTF8.GetBytes(strKey);

            Console.Write("Входной файл: ");
            string inFile = Console.ReadLine();

            Console.Write("Результирующий файл: ");
            string outFile = Console.ReadLine();



            try
            {
                var dfcv2 = new DFCv2(byteKey);

                switch (Menu())
                {
                    case (1):
                        dfcv2.text =
                            dfcv2.ReadByteArrayFromFile(inFile);
                        dfcv2.WriteByteArrayToFile(dfcv2.EncryptText(dfcv2.text),
                            outFile);
                        Console.WriteLine("Сообщение зашифровано!");
                        Console.Read();
                        break;
                    case (2):
                        dfcv2.text =
                            dfcv2.ReadByteArrayFromFile(inFile);
                        dfcv2.WriteByteArrayToFile(dfcv2.DecryptText(dfcv2.text),
                            outFile);
                        Console.WriteLine("Сообщение расшифровано!");
                        Console.Read();
                        break;
                    case (3):
                        Console.Write("Введите ключ: ");
                        strKey = Console.ReadLine();
                        byteKey = Encoding.UTF8.GetBytes(strKey);

                        var dvc = new DFCv2(byteKey);

                        Console.Write("Входной файл: ");
                        inFile = Console.ReadLine();

                        Console.Write("Результирующий файл: ");
                        outFile = Console.ReadLine();
                        break;
                    case (4):
                        Environment.Exit(0);
                        break;

                    default:
                        Console.WriteLine("Такого действия нет!");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Ошибка! Перезапустите программу!");
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private static int Menu()
        {
            Console.Clear();
            Console.WriteLine("Выберите действие:");
            Console.WriteLine(" 1. Шифровать");
            Console.WriteLine(" 2. Дешифровать");
            Console.WriteLine(" 3. Ввести новые данные");
            Console.WriteLine(" 4. Выход");
            Console.Write(" \n\n>>> ");
            string action = Console.ReadLine();
            int act = 0;
            int.TryParse(action, out act);
            Console.Clear();
            return act;
        }
    }
}
