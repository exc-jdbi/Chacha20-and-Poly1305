

//what does Poly1305 mathematically
//https://cr.yp.to/mac/poly1305-20050329.pdf

using System.Numerics;

namespace P1305_MatheTest;

using static RandomHolder;

public class Program
{
  public static void Main()
  {
    for (var i = 0; i < 3; i++)
      TestPoly1305();
    Console.ReadLine();
  }

  static void TestPoly1305()
  {
    var r = RngBytes(16);
    var s = RngBytes(16);
    var size = Rand.Next(10, 128);
    var msg = RngBytes(size);

    var result = TestPoly1305(msg, r, s);
    PrintOut("r", r);
    PrintOut("s", s);
    Console.WriteLine();
    PrintOut("msg", msg);
    Console.WriteLine();
    PrintOut("result", result);
    Console.WriteLine();
    Console.WriteLine();
  }

  static byte[] TestPoly1305(byte[] m, byte[] r, byte[] s)
  {
    int j, i;
    int l = m.Length;
    var result = new byte[16];
    var rbar = BigInteger.Zero;
    for (j = 0; j < 16; ++j)
      rbar += r[j] * BigInteger.Pow(2, 8 * j);

    i = 0;
    var h = BigInteger.Zero;
    var p = (BigInteger.One << 130) - 5;
    while (l > 0)
    {
      var c = BigInteger.Zero;
      for (j = 0; (j < 16) && (j < l); ++j)
        c += m[i + j] * BigInteger.Pow(2, 8 * j);

      c += BigInteger.Pow(2, 8 * j);
      i += j; l -= j;
      h = ((h + c) * rbar) % p;
    }
    for (j = 0; j < 16; ++j)
      h += s[j] * BigInteger.Pow(2, 8 * j);

    for (j = 0; j < 16; ++j)
    {
      var c = (byte)(h % 256);
      h >>= 8;
      result[j] = c;
    }

    return result;
  }

  static void PrintOut(string variable, byte[] bytes)
  {
    Console.Write($"{variable} = ");
    Array.ForEach(bytes, x => Console.Write($"{x} "));
    Console.WriteLine();
  }
}



public class RandomHolder
{
  public static readonly Random Rand = new();

  public static byte[] RngBytes(int size)
  {
    var result = new byte[size];
    Rand.NextBytes(result);
    return result;
  }
}