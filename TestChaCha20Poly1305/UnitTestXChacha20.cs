
using exc.jdbi.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography;

namespace ChaCha20Poly1305Test;

using static RandomHolder;

internal class UnitTestXChacha20
{
  public static void StartUnitTest()
  {
    Console.WriteLine($"{nameof(UnitTestXChacha20)}");
    Console.WriteLine($"*****************");
    Console.WriteLine();

    var round = 10_000;
    Test_Continue(round);
    Test_Continue_Iv_Change(round);
    Test_Instance_Stream(round);
    Test_Instance_File_And_Stream_Stress();

    Console.WriteLine();
  }

  private static void Test_Continue(int rounds)
  {
    Console.Write($"{nameof(Test_Continue)}_Enc ");

    var sw = Stopwatch.StartNew();

    //Gleicher key und iv über eine lange XChaCha20-Instanz.
    //Der CurrentBlock wird immer um 1 hochgezählt.
    //D.h. Key und Iv können als Schlüssel komplett
    //ausgenutzt werden.

    //The XChaCha20 instance is used over a long distance.
    //The same key and Iv is always used.
    //The CurrentBlock is always incremented by 1.
    //I.e. Key and Iv (nonce) can be completely exploited as keys.

    var start = 0;
    var key = RngBytes(32);
    var ciphers = new byte[rounds][];
    using var cc201 = new XChaCha20(key);

    for (var i = 0; i < rounds; i++)
    {
      var size = Rand.Next(10, 128);
      var plain = Enumerable.Range(start, size)
        .Select(x => (byte)x).ToArray();
      start += size;

      //All plains have the same iv, but not
      //the same CurrentBlock.
      //The CurrentBlock is always incremented by 1.
      ciphers[i] = cc201.Encryption(plain);

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");

    start = 0;
    Console.Write($"{nameof(Test_Continue)}_Dec ");

    sw = Stopwatch.StartNew();
    using var cc202 = new XChaCha20(key);

    for (var i = 0; i < rounds; i++)
    {
      var plain = cc202.Decryption(ciphers[i]);

      var expect = Enumerable.Range(start, plain.Length)
        .Select(x => (byte)x).ToArray();
      start += plain.Length;

      if (!plain.SequenceEqual(expect))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");
    Console.WriteLine();
  }

  private static void Test_Continue_Iv_Change(int rounds)
  {
    Console.Write($"{nameof(Test_Continue_Iv_Change)}_Enc ");

    var sw = Stopwatch.StartNew();

    //Auch das geht.
    //Für jeden plain ein neuer iv über eine lange XChaCha20-Instanz.
    //Der CurrentBlock wird trozdem immer um 1 hochgezählt.
    //D.h. Der Key kann als Schlüssel komplett ausgenutzt werden.

    //This is also possible.
    //The XChaCha20 instance is used over a long distance.
    //A new iv is created for each plain.
    //The CurrentBlock is nevertheless always incremented by 1.
    //I.e. The Key can be completely exploited as keys.

    var start = 0;
    var key = RngBytes(32);
    var ciphers = new byte[rounds][];
    using var cc201 = new XChaCha20(key);

    for (var i = 0; i < rounds; i++)
    {
      var size = Rand.Next(10, 128);
      var plain = Enumerable.Range(start, size)
        .Select(x => (byte)x).ToArray();
      start += size;

      //Set new iv for each plain.
      //The CurrentBlock is nevertheless always incremented by 1.
      ciphers[i] = cc201.Encryption(plain, null, true);

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");

    start = 0;
    Console.Write($"{nameof(Test_Continue_Iv_Change)}_Dec ");

    sw = Stopwatch.StartNew();
    using var cc202 = new XChaCha20(key);

    for (var i = 0; i < rounds; i++)
    {
      var plain = cc202.Decryption(ciphers[i]);

      var expect = Enumerable.Range(start, plain.Length)
        .Select(x => (byte)x).ToArray();
      start += plain.Length;

      if (!plain.SequenceEqual(expect))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");
    Console.WriteLine();
  }

  private static void Test_Instance_Stream(int rounds)
  {
    Console.Write($"{nameof(Test_Instance_Stream)} ");

    rounds /= 3;

    var sw = Stopwatch.StartNew();

    for (var i = 0; i < rounds; i++)
    {
      var iv = RngBytes(24);
      var key = RngBytes(32);
      var plain = RngBytes(Rand.Next(10, 128));
      var associated = RngBytes(Rand.Next(1, 16));

      //IV is supplied here.
      using var cc201 = new XChaCha20(key, iv);
      var cipher = cc201.Encryption(plain, associated);

      //No IV needs to be supplied.
      //IV is included in the cipher. 
      using var cc202 = new XChaCha20(key);

      //Now associated must also be given.
      var decipher = cc202.Decryption(cipher, associated);

      if (!plain.SequenceEqual(decipher))
        Debugger.Break();

      using var cc201s = new XChaCha20(key, iv);
      using var plainstream = new MemoryStream(plain);
      using var cipherstream = cc201s.Encryption(plainstream);

      using var cc202s = new XChaCha20(key);
      using var decipherstream = cc202s.Decryption(cipherstream);

      if (!EqualsStream(decipherstream, plainstream))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");
    Console.WriteLine();
  }
  private static void Test_Instance_File_And_Stream(int rounds)
  {
    Console.Write($"{nameof(Test_Instance_File_And_Stream)} ");

    rounds = 100;
    var srcfilename = "data.txt";
    var dstfilename = "cipherdata.txt";
    var decfilename = "decipherdata.txt";
    DeleteAllFile(srcfilename, dstfilename, decfilename);

    var sw = Stopwatch.StartNew();
    for (var i = 0; i < rounds; i++)
    {
      CreateRngFile(srcfilename, Rand.Next(10, 128));

      var iv = RngBytes(8);
      var key = RngBytes(32);

      //An IV is supplied here.
      using var cc201 = new XChaCha20(key, iv);
      cc201.Encryption(srcfilename, dstfilename);

      //No IV needs to be supplied.
      //IV is included in the cipher. 
      using var cc202 = new XChaCha20(key);
      cc202.Decryption(dstfilename, decfilename);

      if (!EqualsFile(srcfilename, decfilename))
        Debugger.Break();

      DeleteAllFile(srcfilename, dstfilename, decfilename);

      if (i % 10 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");
    Console.WriteLine();

  }

  private static void Test_Instance_File_And_Stream_Stress()
  {
    Console.Write($"{nameof(Test_Instance_File_And_Stream_Stress)} ");
    Console.WriteLine($"size = 100Mb; and various tests");
    Console.Write($"... please wait a moment ");

    var srcfilename = "data.txt";
    var dstfilename = "cipherdata.txt";
    var decfilename = "decipherdata.txt";
    DeleteAllFile(srcfilename, dstfilename, decfilename);
    Console.Write(".");

    var sw = Stopwatch.StartNew();

    //Create File 100 Mb !!
    CreateRngFile(srcfilename, 100 * 1024 * 1024);
    Console.Write(".");

    var iv = RngBytes(8);
    var key = RngBytes(32);
    Console.Write(".");

    //An IV is supplied here.
    using var cc201 = new XChaCha20(key);//, iv
    Console.Write(".");

    cc201.Encryption(srcfilename, dstfilename);
    Console.Write(".");

    //No IV needs to be supplied.
    //IV is included in the cipher. 
    using var cc202 = new XChaCha20(key);
    Console.Write(".");

    cc202.Decryption(dstfilename, decfilename);
    Console.Write(".");

    if (!EqualsFile(srcfilename, decfilename))
      Debugger.Break();
    Console.Write(".");

    DeleteAllFile(srcfilename, dstfilename, decfilename);
    Console.Write(".");

    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms;");
    Console.WriteLine();

  }

  private static void CreateRngFile(string filename, int size)
  {
    int s;
    var buffersize = 256 * 256;
    var cntsize = size;
    var buffer = Array.Empty<byte>();

    using var fsout = new FileStream(filename, FileMode.CreateNew, FileAccess.Write);
    while (cntsize != 0)
    {
      s = cntsize >= buffersize ? buffersize : cntsize;
      cntsize -= s;
      if (s != buffer.Length)
        buffer = new byte[s];
      Rand.NextBytes(buffer);
      fsout.Write(buffer, 0, buffer.Length);
    }
  }

  private static void DeleteAllFile(string srcfilename, string destfilename, string decfilename)
  {
    if (File.Exists(srcfilename)) File.Delete(srcfilename);
    if (File.Exists(destfilename)) File.Delete(destfilename);
    if (File.Exists(decfilename)) File.Delete(decfilename);
  }

  private static bool EqualsFile(string srcfilename, string destfilename)
  {
    if (!File.Exists(srcfilename) || !File.Exists(destfilename))
      throw new FileNotFoundException($"Source- or dest-file not found!");

    using var fs1 = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var fs2 = new FileStream(destfilename, FileMode.Open, FileAccess.Read);
    var result = EqualsStream(fs1, fs2);
    return result;
  }


  private static bool EqualsStream(Stream s1, Stream s2)
  {
    if (s1.Length != s2.Length)
      return false;

    using var sha1 = SHA512.Create();
    using var sha2 = SHA512.Create();
    s1.Position = 0;
    s2.Position = 0;
    var result = sha1.ComputeHash(s1).SequenceEqual(sha2.ComputeHash(s2));
    return result;
  }
}
