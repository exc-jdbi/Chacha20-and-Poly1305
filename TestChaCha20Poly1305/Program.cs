

using System.Diagnostics; 

namespace ChaCha20Poly1305Test;
 

public class Program
{
  public static void Main()
  { 

    var sw = Stopwatch.StartNew();

    UnitTestChacha20.StartUnitTest();
    UnitTestXChacha20.StartUnitTest();

    UnitTestPoly1305.StartUnitTest();

    //UnitTestChacha20Poly1305.StartUnitTest();
    //UnitTestXChacha20Poly1305.StartUnitTest();

    sw.Stop();

    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine($"total = {sw.ElapsedMilliseconds}ms");
    Console.WriteLine();
    Console.WriteLine("FINISH");
    Console.WriteLine();
    Console.ReadLine();
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