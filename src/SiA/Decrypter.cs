//
// Decrypter.cs
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
        uint key1;
        uint key2;

        public BinaryFormat Convert(BinaryFormat source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            BinaryFormat decrypted = new BinaryFormat();
            source.Stream.WriteTo(decrypted.Stream);

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

            // Initialize the keys
            key1 = 0x3b9a73c9;
            key2 = 0xc979;

            // Decrypt
            Round0(decrypted.Stream, 0x6d73);

            decrypted.Stream.Position = 0x10;
            Round1(decrypted.Stream);

            Round2(decrypted.Stream);

            return decrypted;
        }

        void Round0(DataStream source, uint key)
        {
            const int MaxBlockSize = 0x100;
            const int MaxIterations = 8;

            // In this round we only decrypt the latest 0x800 bytes
            int encryptedSize = (source.Length - 0x10 > (MaxIterations * MaxBlockSize))
                ? MaxIterations * MaxBlockSize
                : (int)source.Length - 0x10;
            source.PushToPosition(encryptedSize, SeekMode.End);

            key2 = key;

            ushort[] s1 = new ushort[MaxBlockSize * 8];
            ushort[] s2 = new ushort[MaxBlockSize * 8];

            while (source.Position < source.Length) {
                int blockSize = (encryptedSize > MaxBlockSize)
                    ? MaxBlockSize
                    : encryptedSize;

                // Initialize buffer S1
                for (ushort i = 0; i < blockSize * 8; i++) {
                    s1[i] = i;
                }

                // Initialize buffer S2 by permutating S1 with a PRGA
                int s1Index = blockSize * 8;
                for (ushort i = 0; i < blockSize * 8; i++) {
                    // Update the key with a LCG
                    key2 = (key1 * key2) + 0x2f09;
                    int index = ((int)key2 >> 0x10) & 0x7FFF;

                    index %= s1Index;
                    s2[i] = s1[index];

                    Array.Copy(s1, index + 1, s1, index, s1Index - index - 1);
                    s1Index--;
                }

                for (int i = 0; i < blockSize * 4; i++) {
                    ushort k1 = s2[i * 2];
                    uint k1_1 = k1 & 7u;
                    uint k1_2 = (uint)((int)k1 >> 3);

                    ushort k2 = s2[(i * 2) + 1];
                    uint k2_1 = k2 & 7u;
                    uint k2_2 = (uint)((int)k2 >> 3);

                    byte k1_3 = (byte)(1 << (int)k1_1);
                    source.PushToPosition(k1_2, SeekMode.Current);
                    byte b1 = source.ReadByte();
                    uint b1_2 = (uint)(b1 & k1_3);
                    byte b1_w = (byte)(~k1_3);
                    byte b1_3 = (byte)(b1 & b1_w);
                    source.Position--;
                    source.WriteByte(b1_3);
                    source.PopPosition();

                    byte k2_3 = (byte)(1 << (int)k2_1);
                    source.PushToPosition(k2_2, SeekMode.Current);
                    byte b2 = source.ReadByte();
                    uint b2_2 = (uint)(b2 & k2_3);
                    byte b2_w = (byte)(~k2_3);
                    byte b2_3 = (byte)(b2 & b2_w);
                    source.Position--;
                    source.WriteByte(b2_3);
                    source.PopPosition();

                    b2_2 = (uint)(b2_2 >> (int)k2_1);
                    b2_2 = (uint)(b2_2 << (int)k1_1);
                    source.PushToPosition(k1_2, SeekMode.Current);
                    byte o1 = source.ReadByte();
                    byte mix1 = (byte)(b2_2 | o1);
                    source.Position--;
                    source.WriteByte(mix1);
                    source.PopPosition();

                    b1_2 = (uint)(b1_2 >> (int)k1_1);
                    b1_2 = (b1_2 << (int)k2_1);
                    source.PushToPosition(k2_2, SeekMode.Current);
                    byte o2 = source.ReadByte();
                    byte mix2 = (byte)(b1_2 | o2);
                    source.Position--;
                    source.WriteByte(mix2);
                    source.PopPosition();
                }

                source.Seek(blockSize, SeekMode.Current);
                encryptedSize -= blockSize;
            }

            source.PopPosition();
        }

        static void Round1(DataStream source)
        {
            source.PushCurrentPosition();
            DataWriter writer = new DataWriter(source) {
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
                uint tm = (uint)(((ulong)t0 * 0x6A009F01) >> 32);
                uint t1 = tm >> 11; // shift logical
                t1 *= 0x1352u;

                // Decrypt
                uint data = reader.ReadUInt16();
                source.Position -= 2;

                if (t0 - t1 >= 0x9A9)
                    data ^= (ushort)t0;
                data -= (ushort)t0;

                writer.Write((ushort)data);
            }

            // Return to the start position for next round
            source.PopPosition();
        }

        static void Round2(DataStream stream)
        {
        }

        static void Validate(DataStream stream)
        {

        }
    }
}
