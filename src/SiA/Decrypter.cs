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
    using System.Collections.Generic;
    using System.IO;
    using Yarhl.FileFormat;
    using Yarhl.IO;

    public class Decrypter : IConverter<BinaryFormat, BinaryFormat>
    {
        const int HeaderSize = 0x10;

        public BinaryFormat Convert(BinaryFormat source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            // Read the header
            DataReader reader = new DataReader(source.Stream) {
                Endianness = EndiannessMode.BigEndian
            };

            uint format = reader.ReadUInt32();
            uint decompressedSize = reader.ReadUInt32(); // decompressed size
            reader.ReadUInt32(); // reserved
            reader.ReadUInt32(); // reserved

            if (format != 2)
                throw new FormatException("Unknown format " + format);

            byte[] data = new byte[source.Stream.Length - HeaderSize];
            source.Stream.Read(data, 0, data.Length);

            // Round 0 only applies to the latest 0x800 bytes
            int round0Size = (data.Length > 0x800) ? 0x800 : data.Length;
            int round0Pos = data.Length - round0Size;
            Round0(0x6d73, 0, 0x100, data, round0Pos);
            Compare(data, 0);

            Round1(data);
            Compare(data, 1);

            // Last Int32 in big endian is used as part of the multiplier
            // in the generation of random numbers.
            // The other are the expected checksums.
            int multiplierInit = GetInt32BE(data, data.Length - 0x4);
            uint checksum1 = (uint)GetInt32BE(data, data.Length - 0x8);
            uint checksum2 = (uint)GetInt32BE(data, data.Length - 0xC);

            int newSize = Round2(data, multiplierInit);
            Array.Resize(ref data, newSize);
            Compare(data, 2);

            Validate(data, checksum1, checksum2);

            Round0(0x728F, multiplierInit, 0x80, data, 0);
            Compare(data, 3);

            Round4(data);
            Compare(data, 4);

            return new BinaryFormat(data, 0, data.Length);
        }

        static void Compare(byte[] data, int round)
        {
            string basePath = Environment.GetEnvironmentVariable("SIA_WORKDIR");
            string filePath = Path.Combine(basePath, $"round{round}_f.bin");

            using (var original = new DataStream(filePath, FileOpenMode.Read)) {
                using (var source = new DataStream(data, 0, data.Length)) {
                    if (!original.Compare(source)) {
                        string tempFile = Path.Combine(basePath, "temp.bin");
                        source.WriteTo(tempFile);
                        Console.WriteLine($"!! Error on round {round} !!");
                        Environment.Exit(1);
                    }
                }
            }
        }

        static void Round0(int seed, int multiplierInit, int maxBlockSize, byte[] data, int offset)
        {
            var random = new RandomGenerator(seed, multiplierInit);

            IList<ushort> numbers = new List<ushort>(maxBlockSize * 8);
            ushort[] buffer = new ushort[maxBlockSize * 8];

            int MaxSize = 0x800;
            int size = (MaxSize > data.Length) ? data.Length : MaxSize;

            int blockPos = offset;
            while (size > 0) {
                int blockSize = (size > maxBlockSize) ? maxBlockSize : size;

                // Initialize a list with all the possible numbers for this block
                numbers.Clear();
                for (ushort i = 0; i < blockSize * 8; i++) {
                    numbers.Add(i);
                }

                // Initialize buffer permutating the numbers via random generator
                for (ushort i = 0; i < blockSize * 8; i++) {
                    int index = random.NextHigh() % numbers.Count;
                    buffer[i] = numbers[index];
                    numbers.RemoveAt(index);
                }

                // Flags:
                // - Bit 0-2: mask
                // - Bit 3-15: position
                for (int i = 0; i < blockSize * 4; i++) {
                    // Flag 1
                    ushort flags1 = buffer[i * 2];
                    int mask1 = flags1 & 7;
                    int pos1 = flags1 >> 3;

                    int mask = 1 << mask1;
                    int bitsForPos2 = data[blockPos + pos1] & mask;
                    data[blockPos + pos1] &= (byte)(~mask);

                    // Flags 2
                    ushort flags2 = buffer[(i * 2) + 1];
                    int mask2 = flags2 & 7;
                    int pos2 = flags2 >> 3;

                    mask = 1 << mask2;
                    int bitsForPos1 = data[blockPos + pos2] & mask;
                    data[blockPos + pos2] &= (byte)(~mask);

                    // Mix bits
                    bitsForPos1 = (bitsForPos1 >> mask2) << mask1;
                    data[blockPos + pos1] |= (byte)bitsForPos1;

                    bitsForPos2 = (bitsForPos2 >> mask1) << mask2;
                    data[blockPos + pos2] |= (byte)bitsForPos2;
                }

                blockPos += blockSize;
                size -= blockSize;
            }
        }

        static void Round1(byte[] data)
        {
            var random = new RandomGenerator(0xC979);
            int pos = 0;
            while (pos + 1 < data.Length) {
                // Get key component for this iteration
                ushort t0 = random.NextHigh();
                uint t1 = (uint)((t0 * 0x6A009F01L) >> 32);
                t1 = (t1 >> 11) * 0x1352;

                // Decrypt
                ushort value = (ushort)GetUInt16BE(data, pos);

                if (t0 - t1 >= 0x9A9)
                    value ^= t0;
                value -= t0;

                data[pos++] = (byte)(value >> 8);
                data[pos++] = (byte)(value & 0xFF);
            }
        }

        static int Round2(byte[] data, int multiplierInit)
        {
            // Search end of data to get the encryption size
            int size = data.Length - 0xD;
            while (data[size] == 0x00)
                size--;

            // The last byte of the data must be 0xFF
            if (data[size] != 0xFF)
                throw new FormatException("Invalid stream");

            // For each block, there is a different random number generator
            int[] blockSizes = { 0x1F, 0x1D, 0x17 };
            var generators = new RandomGenerator[] {
                new RandomGenerator(0xA9BB, multiplierInit),
                new RandomGenerator(0x892D, multiplierInit),
                new RandomGenerator(0x8939, multiplierInit)
            };

            int blockIdx = 0;
            int pos = 0;
            while (pos < size) {
                var generator = generators[blockIdx % 3];
                int blockSize = blockSizes[blockIdx % 3];
                blockSize += blockIdx / 3;

                for (int j = 0; j < blockSize && pos < size; j++) {
                    byte key = (byte)(generator.NextHigh() & 0xFF);
                    data[pos++] ^= key;
                }

                blockIdx++;
            }

            // Double check that we end with this file
            if (data[pos] != 0xFF)
                throw new FormatException("Error decrypting round 2");

            // Ok good, then we can overwrite as 0
            data[pos] = 0x00;

            return size;
        }

        static void Validate(byte[] data, uint expected1, uint expected2)
        {
            uint checksum1 = 0;
            uint checksum2 = 0;
            for (int i = 0; i < data.Length / 4; i++) {
                uint value = (uint)GetInt32BE(data, i * 4);
                checksum1 ^= ~value;
                checksum2 -= value;
            }

            if (checksum1 != expected1)
                throw new FormatException("Invalid checksum 1");

            if (checksum2 != expected2)
                throw new FormatException("Invalid checksum 2");
        }

        static void Round4(byte[] data)
        {
            // Read header
            int decompressedSize = GetInt32BE(data, 0);
            int dataOffset = GetInt32BE(data, 4);
            int totalSize = GetInt32BE(data, 8);
        }

        static int GetInt32BE(byte[] data, int offset)
        {
            return (data[offset] << 24) |
                (data[offset + 1] << 16) |
                (data[offset + 2] << 8) |
                data[offset + 3];
        }

        static ushort GetUInt16BE(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }
    }
}
