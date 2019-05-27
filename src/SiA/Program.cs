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
            Console.WriteLine(
                "v{0} ~~ by pleonex ~~",
                Assembly.GetExecutingAssembly().GetName().Version);
            Console.WriteLine();

            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help") {
                PrintHelp();
            }

            string mode = args[0];
            if (mode == "-f" && args.Length == 2) {
                string input = Path.GetFullPath(args[1]);
                string output = Path.Combine(
                    Path.GetDirectoryName(input),
                    Path.GetFileNameWithoutExtension(input));
                Console.WriteLine($"Decrypting to {output}");
                Decrypt(input, output);
            } else if (mode == "-d" && args.Length == 3) {
                string input = Path.GetFullPath(args[1]);
                string output = Path.GetFullPath(args[2]);
                DecryptFolder(input, output);
            } else {
                PrintHelp();
            }

            Console.WriteLine("Done!");
        }

        static void PrintHelp()
        {
            Console.WriteLine("USAGE:");
            Console.WriteLine("* Decrypt file: SiA.exe -f file_path");
            Console.WriteLine("* Decrypt all files from dir: SiA.exe -d inDir outDir");

            Console.WriteLine("Press enter to quit");
            Console.ReadLine();
            Environment.Exit(1);
        }

        static void Decrypt(string encryptedFile, string decryptedFile)
        {
            using (Node file = NodeFactory.FromFile(encryptedFile)) {
                file.TransformWith<Decrypter>();
                file.Stream.WriteTo(decryptedFile);
            }
        }

        static void DecryptFolder(string inFolder, string outFolder)
        {
            var encryptedFiles = Directory.EnumerateFiles(
                inFolder,
                "*.xml.e",
                SearchOption.AllDirectories);
            foreach (var encrypted in encryptedFiles) {
                string name = Path.GetFileNameWithoutExtension(encrypted);
                string directory = Path.GetDirectoryName(encrypted);
                string relative = directory.Remove(0, inFolder.Length + 1);
                string output = Path.Combine(outFolder, relative, name);

                Console.WriteLine($"* {relative}/{name}");
                Decrypt(encrypted, output);
            }
        }
    }
}
