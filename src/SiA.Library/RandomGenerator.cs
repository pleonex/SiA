//
// RandomGenerator.cs
//
// Author:
//       Benito Palacios Sanchez <benito356@gmail.com>
//
// Copyright (c) 2019 Benito Palacios Sanchez
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
namespace SiA.Library
{
    /// <summary>
    /// Linear congruential generator of random numbers of the encryption
    /// algorithm.
    /// </summary>
    public class RandomGenerator
    {
        const int BaseMultiplier = 0x3b9a73c9;

        int current;

        public RandomGenerator(int seed)
        {
            Multiplier = BaseMultiplier;
            current = seed;
        }

        public RandomGenerator(int seed, int incrementMultiplier)
        {
            Multiplier = BaseMultiplier + incrementMultiplier;
            current = seed;
        }

        public static int Increment => 0x2f09;

        public int Multiplier {
            get;
            private set;
        }

        public int Next()
        {
            current = (Multiplier * current) + Increment;
            return current;
        }

        public ushort NextHigh()
        {
            // Do the shift with unsigned to avoid carrying the sign bit
            // Remove the sign bit.
            return (ushort)(((uint)Next() >> 16) & 0x7FFF);
        }
    }
}
