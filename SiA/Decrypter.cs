//
// Encryption.cs
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
    using Yarhl.FileFormat;
    using Yarhl.IO;

    public class Decrypter : IConverter<BinaryFormat, BinaryFormat>
    {
        public BinaryFormat Convert(BinaryFormat source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            BinaryFormat decrypted = new BinaryFormat();


            // Read the header
            DataReader reader = new DataReader(source.Stream) {
                Endianness = EndiannessMode.BigEndian
            };
            uint format = reader.ReadUInt32();
            reader.ReadUInt32(); // decompressed size
            reader.ReadUInt32(); // reserved
            reader.ReadUInt32(); // reserved

            if (format != 2)
                throw new FormatException("Unknown format " + format);

            // Decrypt
            Round1(source.Stream, decrypted.Stream);
            Round2(decrypted.Stream);

            return decrypted;
        }

        static void Round1(DataStream source, DataStream destination)
        {
            destination.PushCurrentPosition();
            DataWriter writer = new DataWriter(destination) {
                Endianness = EndiannessMode.BigEndian
            };
            DataReader reader = new DataReader(source) {
                Endianness = EndiannessMode.BigEndian
            };

            // Initialize the keys
            uint key1 = 0x3B9A73C9;
            uint key2 = 0x0000C979;

            while (!source.EndOfStream) {
                // Update key
                key2 = (key1 * key2) + 0x2F09;

                // Get key component for this iteration
                uint t0 = (uint)((int)key2 >> 16) & 0x7FFF;  // shift arithmetical
                uint t1 = (uint)(t0 * 0x6A009F01u) >> 11; // shift logical
                t1 *= 0x1352u;

                // Decrypt
                uint data = reader.ReadUInt16();

                if (t0 - t1 >= 0x9A9)
                    data ^= (ushort)t0;
                data -= (ushort)t0;

                writer.Write((ushort)data);
            }

            // Return to the start position for next round
            destination.PopPosition();
        }

        static void Round2(DataStream stream)
        {
            
        }
    }
}
