using exc.jdbi.Cryptography;
using System.Diagnostics;

namespace ChaCha20Poly1305Test;

using static RandomHolder;

internal class UnitTestPoly1305
{



  public static void StartUnitTest()
  {
    Console.WriteLine($"{nameof(UnitTestPoly1305)}");
    Console.WriteLine($"****************");
    Console.WriteLine();


    var round = 10_000;
    Test_Hmac_Difference();
    Test_Poly1305_First(round);
    Test_Poly1305(round);
    Test_Poly1305_Stream(round);
    Test_Poly1305_File(round);


    Console.WriteLine();
  }

  private static void Test_Hmac_Difference()
  {
    //https://datatracker.ietf.org/doc/html/rfc8439#section-2.7
    //Poly1305 is not a suitable choice for a PRF.
    //(IKEv2 >> a function that accepts a variable-
    //length key and a variable-length input)
    //Poly1305 prohibits using the same key twice,
    //whereas the PRF in IKEv2 is used multiple times
    //with the same key.
    //Additionally, unlike HMAC, Poly1305 is biased,
    //so using it for key derivation would reduce the
    //security of the symmetric encryption.

    // !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! 
    //A Hmac must not simply be replaced with Poly1305.
    // !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! !!!!!!!!!! 

  }

  private static void Test_Poly1305_First(int round)
  {
    Console.Write($"{nameof(Test_Poly1305_First)} ");

    int size = 0;
    var sw = Stopwatch.StartNew();

    for (var i = 0; i < round; i++)
    {
      size = 8 + i;
      var key = RngBytes(32);
      var bytes = RngBytes(size);

      using var hmac = new Poly1305(key);
      var hash1 = hmac.ComputeHash(bytes);
      var hash2 = hmac.ComputeHash(bytes);

      //Note: The hashvalues are always the same here.
      if (!hash1.SequenceEqual(hash2))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {round}; size = {size}");

  }


  private static void Test_Poly1305(int round)
  {
    Console.Write($"{nameof(Test_Poly1305)} ");

    int size = 0;
    var sw = Stopwatch.StartNew();

    for (var i = 0; i < round; i++)
    {
      size = 1024;
      var key = RngBytes(32);
      var bytes = RngBytes(size);

      using var hmac = new Poly1305(key);
      var hash1 = hmac.ComputeHash(bytes);
      var hash2 = hmac.ComputeHash(bytes);

      //Note: The hashvalues are always the same here.
      if (!hash1.SequenceEqual(hash2))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {round}; size = {size}");
  }


  private static void Test_Poly1305_Stream(int round)
  {
    Console.Write($"{nameof(Test_Poly1305_Stream)} ");

    int size = 0;
    var sw = Stopwatch.StartNew();

    for (var i = 0; i < round; i++)
    {
      size = 1024;
      var key = RngBytes(32);
      var bytes = RngBytes(size);
      using var streambytes = new MemoryStream(bytes);

      using var hmac = new Poly1305(key);
      var hash = hmac.ComputeHash(bytes);

      using var hmacstream = new Poly1305(key);
      var hashstream = hmacstream.ComputeHash(streambytes);

      if (!hash.SequenceEqual(hashstream))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {round}; size = {size}");
  }

  private static void Test_Poly1305_File(int round)
  {

    round = 100;
    var srcfilename = "data.txt";
    Console.Write($"{nameof(Test_Poly1305_File)} ");

    int size = 0;
    var sw = Stopwatch.StartNew();

    for (var i = 0; i < round; i++)
    {
      size = 1024;
      var key = RngBytes(32);
      var bytes = RngBytes(size);

      using (var fsoutput = new FileStream(srcfilename, FileMode.Create, FileAccess.Write))
        fsoutput.Write(bytes, 0, bytes.Length);

      using var hmac = new Poly1305(key);
      var hash = hmac.ComputeHash(bytes);

      using (var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read))
      {
        using var hmacstream = new Poly1305(key);
        var hashstream = hmacstream.ComputeHash(fsinput);

        if (!hash.SequenceEqual(hashstream))
          Debugger.Break();
      }

      if (File.Exists(srcfilename)) File.Delete(srcfilename);

      if (i % 10 == 0) Console.Write(".");
    }

    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {round}; size = {size}");
    Console.WriteLine();
  }
}
