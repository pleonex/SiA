//
// Program.cs
//
// Author:
//       Benito Palacios Sanchez <benito356@gmail.com>
//
// Copyright (c) 2018 Benito Palacios Sanchez
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
namespace SiA
{
    using System;
    using System.IO;
    using System.Reflection;
    using Yarhl.FileFormat;
    using Yarhl.FileSystem;

    static class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("SiA -- Decrypter for NoA files");
            Console.WriteLine("v{0} ~~ by pleonex ~~", Assembly.GetExecutingAssembly().GetName().Version);
            Console.WriteLine();

            string encryptedFile;
            if (args.Length != 1) {
                Console.Write("Encrypted file: ");
                encryptedFile = Console.ReadLine();
            } else {
                encryptedFile = args[0];
            }

            string decryptedFile = Path.Combine(
                Path.GetDirectoryName(encryptedFile),
                Path.GetFileNameWithoutExtension(encryptedFile));
            Console.WriteLine("Decrypted file: {0}", decryptedFile);

            Decrypt(encryptedFile, decryptedFile);

            Console.WriteLine("Done!");
        }

        static void Decrypt(string encryptedFile, string decryptedFile)
        {
            Node file = NodeFactory.FromFile(encryptedFile);
            file.Transform<BinaryFormat>(converter: new Decrypter());
            file.GetFormatAs<BinaryFormat>().Stream.WriteTo(decryptedFile);
        }
    }
}
