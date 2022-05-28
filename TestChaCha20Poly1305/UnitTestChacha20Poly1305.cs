

using System.Diagnostics;
using System.Security.Cryptography;
using exc.jdbi.Cryptography;

namespace ChaCha20Poly1305Test;

using static RandomHolder;

internal class UnitTestChacha20Poly1305
{

  public static void StartUnitTest()
  {
    Console.WriteLine($"{nameof(UnitTestChacha20Poly1305)}");
    Console.WriteLine($"************************");
    Console.WriteLine();

    var rounds = 10_000;
    Test_Instance(rounds);
    Test_Continue(rounds);
    Test_Instance_Stream(rounds);
    Test_Instance_File_And_Stream(rounds);
    Test_Instance_File_And_Stream_Stress();

    Console.WriteLine();
  }


  private static void Test_Instance(int rounds)
  {
    Console.Write($"{nameof(Test_Instance)}_1 ");

    rounds /= 2;

    var sw = Stopwatch.StartNew();

    for (var i = 0; i < rounds; i++)
    {
      var iv = RngBytes(12);
      var key = RngBytes(32);
      var aad = RngBytes(12);
      var plain = RngBytes(Rand.Next(10, 128));

      //An IV is supplied here.
      using var cp1 = new ChaCha20Poly1305Ex(key, iv);
      var cipher = cp1.Encryption(plain, aad);

      //No IV needs to be supplied.
      //IV is included in the cipher.
      using var cp2 = new ChaCha20Poly1305Ex(key);
      var decipher = cp2.Decryption(cipher, aad);

      if (!plain.SequenceEqual(decipher))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");

    Console.Write($"{nameof(Test_Instance)}_2 ");

    sw = Stopwatch.StartNew();
    for (var i = 0; i < rounds; i++)
    {
      var key = RngBytes(32);
      var size = Rand.Next(1, 28);
      var aad = RngBytes(size);
      var plain = RngBytes(Rand.Next(10, 128));

      //The iv is randomly generated, and supplied
      //with the cipher.
      using var cc201 = new ChaCha20Poly1305Ex(key);
      var cipher = cc201.Encryption(plain, aad);

      using var cc202 = new ChaCha20Poly1305Ex(key);
      var decipher = cc202.Decryption(cipher, aad);

      if (!plain.SequenceEqual(decipher))
        Debugger.Break();

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");
    Console.WriteLine();
  }


  private static void Test_Continue(int rounds)
  {
    Console.Write($"{nameof(Test_Continue)}_Enc ");

    //Einer der Vorteile, wenn der Algo so konzipiert ist.
    //Die gleiche ChaCha20Poly1305-Instanz wird über eine
    //lange Strecke genutzt. Der interne Counter wird immer um
    //1 hochgezählt, damit rechtzeitig abgebrochen wird.
    //Der iv (nonce) wird in Chacha20 über eine Strecke von 2^32
    //voll ausgenutzt, was einer Verschlüsselungsstrecke in
    //Chacha20Poly1305 von 64 * 2^32 (ca.256Gb) entspricht. 

    //The same ChaCha20Poly1305 instance is used over a long distance.
    //The internal counter is always incremented by 1, so that it is aborted in time.
    //The iv (nonce) is fully utilized in Chacha20 over a distance of 2^32,
    //which corresponds to an encryption distance in Chacha20Poly1305
    //of 64 * 2^32 (approx.256Gb). 
    //https://datatracker.ietf.org/doc/html/rfc7539#section-2.8
    var start = 0;
    var key = RngBytes(32);
    var aad = RngBytes(Rand.Next(1, 28));
    var ciphers = new byte[rounds][];
    var sw = Stopwatch.StartNew();

    //Create an instance once.
    //The iv is randomly generated, and supplied
    //with the cipher.
    using var cc201 = new ChaCha20Poly1305Ex(key);

    for (var i = 0; i < rounds; i++)
    {
      var size = Rand.Next(10, 128);
      var plain = Enumerable.Range(start, size)
        .Select(x => (byte)x).ToArray();
      start += size;

      //The same iv is always supplied.
      //All cipher have the same iv.
      ciphers[i] = cc201.Encryption(plain, aad);

      if (i % 1000 == 0) Console.Write(".");
    }
    Console.WriteLine($" t = {sw.ElapsedMilliseconds}ms; r = {rounds}");

    start = 0;
    Console.Write($"{nameof(Test_Continue)}_Dec ");

    sw = Stopwatch.StartNew();

    //Create an instance once.
    using var cc202 = new ChaCha20Poly1305Ex(key);

    for (var i = 0; i < rounds; i++)
    {
      var plain = cc202.Decryption(ciphers[i], aad);

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
      var iv = RngBytes(12);
      var key = RngBytes(32);
      var aad = RngBytes(Rand.Next(1, 28));
      var plain = RngBytes(Rand.Next(10, 128));

      //An IV is supplied here.
      using var cc201 = new ChaCha20Poly1305Ex(key, iv);
      var cipher = cc201.Encryption(plain, aad);

      //No IV needs to be supplied.
      //IV is included in the cipher. 
      using var cc202 = new ChaCha20Poly1305Ex(key);
      //Now associated must also be given.
      var decipher = cc202.Decryption(cipher, aad);

      if (!plain.SequenceEqual(decipher))
        Debugger.Break();

      using var cc201s = new ChaCha20Poly1305Ex(key, iv);
      using var plainstream = new MemoryStream(plain);
      using var cipherstream = cc201s.Encryption(plainstream, aad);

      using var cc202s = new ChaCha20Poly1305Ex(key);
      using var decipherstream = cc202s.Decryption(cipherstream, aad);

      if (!EqualsStream(decipherstream, plainstream))
        Debugger.Break();

      if (!EqualsStream(decipherstream, plain))
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

      var iv = RngBytes(12);
      var key = RngBytes(32);
      var aad = RngBytes(Rand.Next(1, 28));

      //An IV is supplied here.
      using var cc201 = new ChaCha20Poly1305Ex(key, iv);
      cc201.Encryption(srcfilename, dstfilename, aad);

      //No IV needs to be supplied.
      //IV is included in the cipher. 
      using var cc202 = new ChaCha20Poly1305Ex(key);
      cc202.Decryption(dstfilename, decfilename, aad);

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

    var iv = RngBytes(12);
    var key = RngBytes(32);
    var aad = RngBytes(Rand.Next(1, 28));
    Console.Write(".");

    //An IV is supplied here.
    using var cc201 = new ChaCha20Poly1305Ex(key);//, iv
    Console.Write(".");

    cc201.Encryption(srcfilename, dstfilename, aad);
    Console.Write(".");

    //No IV needs to be supplied.
    //IV is included in the cipher. 
    using var cc202 = new ChaCha20Poly1305Ex(key);
    Console.Write(".");

    cc202.Decryption(dstfilename, decfilename, aad);
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
    using var sha1 = SHA512.Create();
    using var sha2 = SHA512.Create();
    s1.Position = 0; s2.Position = 0;
    var result = sha1.ComputeHash(s1).SequenceEqual(sha2.ComputeHash(s2));
    return result;
  }
  private static bool EqualsStream(Stream s1, byte[] bytes)
  {
    using var sha1 = SHA512.Create();
    using var sha2 = SHA512.Create();
    s1.Position = 0;
    var result = sha1.ComputeHash(s1).SequenceEqual(sha2.ComputeHash(bytes));
    return result;
  }
}
