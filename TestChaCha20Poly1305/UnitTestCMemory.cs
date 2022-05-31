

using exc.jdbi.Cryptography;
using System.Diagnostics;

namespace ChaCha20Poly1305Test;

using R = RandomHolder;

//CMemory is a class that secures and manages memory
//in Unsafe. Is designed for Windows.

internal class UnitTestCMemory
{
  public static void StartUnitTest()
  {
    Console.WriteLine($"{nameof(UnitTestCMemory)}");
    Console.WriteLine($"****************");
    Console.WriteLine();

    Int32Test();
    CharTest();
    BoolTest();


    Console.WriteLine();
  }

  private static void Int32Test()
  {
    DisposableI32Test();
    StressTestI32(10);
    TestCopyToFromI32();

    TestCopyI32();
    TestInstanceI32();
    TestOperationI32();
    Console.WriteLine();
  }

  private static void CharTest()
  {
    DisposableCharTest();
    TestCopyToFromChar();
    TestCopyChar();
    Console.WriteLine();
  }

  private static void BoolTest()
  {
    //With bool data type no encryption !!

    DisposableBoolTest();
    Console.WriteLine();
  }

  private static void DisposableBoolTest()
  {
    //With bool data type no encryption !!

    Console.Write($"{nameof(DisposableBoolTest)} ");
    var cnt = 100;
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < cnt; i++)
    {
      var size = 10L;
      using (var cmem = new CMemory<bool>(size))
      {
        for (long j = 0; j < cmem.LongLength; j++)
        {
          var b = ToRngBools(3)[1];
          cmem[j] = b;
          Debug.Assert(b == cmem[j]);
        }
      }

      var src = ToRngBools(10);
      //
      using (var cmem1 = new CMemory<bool>(src))
      using (var cmem2 = new CMemory<bool>(src))
      {
        Debug.Assert(cmem1.Equality(cmem2));
        for (long j = 0; j < cmem1.LongLength; j++)
        {
          var b1 = cmem1[j] ? 1 : 0;
          var b2 = cmem2[(j + 1) % cmem2.Length] ? 1 : 0;
          var b3 = cmem2[j] ? 1 : 0;
          var b4 = cmem1[(j + 1) % cmem1.Length] ? 1 : 0;

          var number = b1 + b2;
          Debug.Assert(number == b3 + b4);
          Debug.Assert(number == (src[j] ? 1 : 0) + (src[(j + 1) % src.Length] ? 1 : 0));
        }
        cmem1.SetMemoryZeroNumbers();
      }
      if (i % 10 == 0)
        Console.Write(".");
    }
    Console.Write($" t = {sw.ElapsedMilliseconds / cnt}ms");
    Console.WriteLine();
  }

  private static void DisposableCharTest()
  {
    Console.Write($"{nameof(DisposableCharTest)} ");
    var cnt = 100;
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < cnt; i++)
    {
      var size = 10L;
      using (var cmem = new CMemory<char>(size))
      {
        for (long j = 0; j < cmem.LongLength; j++)
        {
          var c = ToRngChar();
          cmem[j] = c;
          Debug.Assert(c == cmem[j]);
        }
      }

      var src = ToRngChars(10);
      //
      using (var cmem1 = new CMemory<char>(src))
      using (var cmem2 = new CMemory<char>(src))
      {
        Debug.Assert(cmem1.Equality(cmem2));
        for (long j = 0; j < cmem1.LongLength; j++)
        {
          var number = cmem1[j] + cmem2[(j + 1) % cmem2.Length];
          Debug.Assert(number == cmem2[j] + cmem1[(j + 1) % cmem1.Length]);
          Debug.Assert(number == src[j] + src[(j + 1) % src.Length]);
        }
        cmem1.SetMemoryZeroNumbers();
      }

      src = "exc-jdbi".ToCharArray();
      using (var cmem1 = new CMemory<char>(src))
      using (var cmem2 = new CMemory<char>(src))
      {
        Debug.Assert(cmem1.Equality(cmem2));
        for (long j = 0; j < cmem1.LongLength; j++)
        {
          var number = cmem1[j] + cmem2[(j + 1) % cmem2.Length];
          Debug.Assert(number == cmem2[j] + cmem1[(j + 1) % cmem1.Length]);
          Debug.Assert(number == src[j] + src[(j + 1) % src.Length]);
        }
        cmem1.SetMemoryZeroNumbers();
      }
      if (i % 10 == 0)
        Console.Write(".");
    }
    Console.Write($" t = {sw.ElapsedMilliseconds / cnt}ms");
    Console.WriteLine();

  }

  private static void TestCopyToFromChar()
  {
    Console.Write($"{nameof(TestCopyToFromChar)} ");
    //Test Array CopyTo
    char[] a;
    int skip;
    var src = "exc-jdbi".ToCharArray();
    var src2 = Array.Empty<char>();
    for (var i = 0; i < 10; i++)
    {
      src2 = ToRngChars(20);
      skip = R.Rand.Next(src2.Length - src.Length + 1);
      src.CopyTo(src2, skip);
      a = src2.Skip(skip).Take(src.Length).ToArray();
      Debug.Assert(a.SequenceEqual(src));
    }


    //TestMemoryAllocation();
    var cmem = new CMemory<char>(src);
    Debug.Assert(cmem.Equality(src));
    src = null;
    //Debug.Assert(!cmem.Equality(src)); //Exception
    Debug.Assert(!cmem.Equality(Array.Empty<char>()));

    src = ToRngChars(20);
    skip = R.Rand.Next(src.Length - cmem.Length + 1);
    cmem.CopyTo(src, skip);
    a = src.Skip(skip).Take(cmem.Length).ToArray();
    Debug.Assert(cmem.Equality(a));
    var result = cmem.ToArray();

    src = "exc-jdbi".ToCharArray();
    var cmem2 = new CMemory<char>(src);
    cmem.NewInit(ToRngChars(20));
    src = null;
    skip = R.Rand.Next(cmem.Length - cmem2.Length + 1);
    cmem2.CopyTo(cmem, skip);
    a = cmem.SkipTake(skip, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();

    src = ToRngChars(20);
    cmem2.NewInit(src);
    src = "exc-jdbi".ToCharArray();
    skip = R.Rand.Next(cmem2.Length - src.Length + 1);
    cmem2.CopyFrom(src, skip);
    a = cmem2.SkipTake(skip, src.Length);
    Debug.Assert(src.SequenceEqual(a));
    result = cmem2.ToArray();
    cmem.Dispose();
    cmem2.Dispose();

    src = ToRngChars(20);
    cmem = new CMemory<char>(src);
    cmem2 = new CMemory<char>("exc-jdbi".ToCharArray());

    src = null;
    skip = R.Rand.Next(cmem.Length - cmem2.Length + 1);
    cmem.CopyFrom(cmem2, skip);
    a = cmem.SkipTake(skip, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();
    cmem2.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }


  private static void TestCopyChar()
  {
    Console.Write($"{nameof(TestCopyChar)} ");
    var chars1 = ToRngChars(20);
    var cmem = new CMemory<char>(chars1);

    var chars2 = "exc-jdbi".ToCharArray();
    var skip1 = R.Rand.Next(cmem.Length - chars2.Length + 1);
    var skip2 = R.Rand.Next(chars2.Length - 3);
    var len2 = R.Rand.Next(1, chars2.Length - skip2 + 1);
    CMemory.Copy(chars2, skip2, cmem, skip1, len2);
    var a = cmem.SkipTake(skip1, len2);
    Debug.Assert(chars2.Skip(skip2).Take(len2).SequenceEqual(a));
    var result = cmem.ToArray();
    CMemory.Copy(chars2, 0, cmem, 1, chars2.Length);
    a = cmem.SkipTake(1, chars2.Length);
    Debug.Assert(chars2.SequenceEqual(a));
    result = cmem.ToArray();
    cmem.Dispose(); //WICHTIG

    //andere zwei auch noch prüfen.
    var cmem2 = new CMemory<char>(chars2); //size 10
    cmem = new CMemory<char>(chars1); //size 20
    chars1 = null; chars2 = null;
    skip1 = R.Rand.Next(cmem.Length - cmem2.Length + 1);
    skip2 = R.Rand.Next(cmem2.Length - 3);
    len2 = R.Rand.Next(1, cmem2.Length - skip2 + 1);
    CMemory.Copy(cmem2, skip2, cmem, skip1, len2);
    a = cmem.SkipTake(skip1, len2);
    Debug.Assert(cmem2.SkipTake(skip2, len2).SequenceEqual(a));
    result = cmem.ToArray();
    CMemory.Copy(cmem2, 0, cmem, 1, cmem2.Length);
    a = cmem.SkipTake(1, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();
    cmem2.Dispose();

    chars1 = "exc-jdbi".ToCharArray();
    cmem = new CMemory<char>(chars1);
    chars2 = ToRngChars(20);
    skip1 = R.Rand.Next(cmem.Length - 2);
    skip2 = R.Rand.Next(chars2.Length - cmem.Length + 1);
    len2 = R.Rand.Next(1, cmem.Length - skip1 + 1);
    CMemory.Copy(cmem, skip1, chars2, skip2, len2);
    a = cmem.SkipTake(skip1, len2);
    Debug.Assert(chars2.Skip(skip2).Take(len2).SequenceEqual(a));
    CMemory.Copy(cmem, 0, chars2, 3, cmem.Length);
    Debug.Assert(cmem.Equality(chars2.Skip(3).Take(cmem.Length).ToArray()));

    cmem.Dispose();
    cmem2.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }

  private static void DisposableI32Test()
  {
    Console.Write($"{nameof(DisposableI32Test)} ");
    var cnt = 100;
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < cnt; i++)
    {
      var size = 10L;
      using (var cmem = new CMemory<int>(size))
      {
        for (long j = 0; j < cmem.LongLength; j++)
        {
          var r = R.Rand.Next();
          cmem[j] = r;
          Debug.Assert(r == cmem[j]);
        }
      }

      var src = ToRngInts(10);
      //
      using (var cmem1 = new CMemory<int>(src))
      using (var cmem2 = new CMemory<int>(src))
      {
        Debug.Assert(cmem1.Equality(cmem2));
        for (long j = 0; j < cmem1.LongLength; j++)
        {
          var number = cmem1[j] + cmem2[(j + 1) % cmem2.Length];
          Debug.Assert(number == cmem2[j] + cmem1[(j + 1) % cmem1.Length]);
          Debug.Assert(number == src[j] + src[(j + 1) % src.Length]);
        }
        cmem1.SetMemoryZeroNumbers();
      }
      if (i % 10 == 0)
        Console.Write(".");
    }
    Console.Write($" t = {sw.ElapsedMilliseconds / cnt}ms");
    Console.WriteLine();
  }

  private static void TestCopyToFromI32()
  {
    Console.Write($"{nameof(TestCopyToFromI32)} ");
    //Test Array CopyTo
    int[] a;
    int skip;
    var src = Enumerable.Range(0, 5).ToArray();
    var src2 = Enumerable.Range(100, 10).Reverse().ToArray();
    for (var i = 0; i < 10; i++)
    {
      src2 = ToRngInts(10);
      skip = R.Rand.Next(6);
      src.CopyTo(src2, skip);
      a = src2.Skip(skip).Take(src.Length).ToArray();
      Debug.Assert(a.SequenceEqual(src));
    }


    //TestMemoryAllocation();
    src = Enumerable.Range(0, 5).ToArray();
    var cmem = new CMemory<int>(src);
    Debug.Assert(cmem.Equality(src));
    src = null;
    //Debug.Assert(!cmem.Equality(src)); //Exception
    Debug.Assert(!cmem.Equality(Array.Empty<int>()));

    src = Enumerable.Range(100, 10).ToArray();
    skip = R.Rand.Next(6);
    cmem.CopyTo(src, skip);
    a = src.Skip(skip).Take(cmem.Length).ToArray();
    Debug.Assert(cmem.Equality(a));
    var result = cmem.ToArray();

    src = Enumerable.Range(100, 3).ToArray();
    var cmem2 = new CMemory<int>(src);
    src = null;
    skip = R.Rand.Next(3);
    cmem2.CopyTo(cmem, skip);
    a = cmem.SkipTake(skip, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();

    src = Enumerable.Range(0, 5).ToArray();
    cmem2.NewInit(src);
    src = null;
    src = Enumerable.Range(100, 3).ToArray();
    skip = R.Rand.Next(3);
    cmem2.CopyFrom(src, skip);
    a = cmem2.SkipTake(skip, src.Length);
    Debug.Assert(src.SequenceEqual(a));
    result = cmem2.ToArray();
    cmem.Dispose();

    src = Enumerable.Range(1000, 10).ToArray();
    cmem = new CMemory<int>(src);
    src = null;
    skip = R.Rand.Next(6);
    cmem.CopyFrom(cmem2, skip);
    a = cmem.SkipTake(skip, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();
    cmem2.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }

  private static void StressTestI32(int count)
  {
    Console.Write($"{nameof(StressTestI32)} ");
    var cnt = 1_000_000;
    var sw = Stopwatch.StartNew();
    for (var i = 0; i < count; i++)
    {
      var ints = ToRngInts(cnt);
      var cmem = new CMemory<int>(ints);
      ints = null;
      cmem.Free();
      cmem.Dispose();
      Console.Write(".");
    }
    Console.Write($" t = {sw.ElapsedMilliseconds / count}ms; size = {cnt:0,0}");
    Console.WriteLine();
  }

  private static void TestInstanceI32()
  {
    Console.Write($"{nameof(TestInstanceI32)} ");
    ////Wirft eine Exception.
    //var cmem = new CMemory<int>(null);

    var ints = ToRngInts(1_000);
    var cmem = new CMemory<int>(ints);
    ints = null;
    cmem.Free();
    cmem.Dispose();

    ints = ToRngInts(1_000);
    cmem = new CMemory<int>(ints);
    var cmem2 = new CMemory<int>(new[] { 0, 1, 2, 3, 4 });
    cmem2.NewInit(cmem);
    //Reference-Check
    Debug.Assert(cmem.Equality(cmem));
    //ValueCheck
    Debug.Assert(cmem.Equality(cmem2));
    cmem.Dispose();
    cmem2.Dispose();

    ints = ToRngInts(1_000);
    cmem = new CMemory<int>(ints);
    ints = null;
    cmem.SetMemoryZeroNumbers();
    cmem.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }

  private static void TestOperationI32()
  {
    Console.Write($"{nameof(TestOperationI32)} ");
    var cmem1 = new CMemory<int>(new[] { 5 });
    var cmem2 = new CMemory<int>(new[] { 10 });
    var cmem3 = new CMemory<int>(new[] { cmem1[0] + cmem2[0] });
    var number1 = cmem1[0] + cmem2[0];
    Debug.Assert(number1 == 5 + 10);
    Debug.Assert(number1 == cmem3[0]);

    var cmem4 = new CMemory<int>(1);
    cmem4[0] = cmem1[0] + cmem2[0];
    var number2 = cmem4[0];

    cmem1.Dispose();
    cmem2.Dispose();
    cmem3.Dispose();
    cmem4.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }

  private static void TestCopyI32()
  {
    Console.Write($"{nameof(TestCopyI32)} ");
    var ints1 = Enumerable.Range(1000, 20).ToArray();
    var cmem = new CMemory<int>(ints1);
    var ints2 = Enumerable.Range(10, 10).Reverse().ToArray();
    var skip1 = R.Rand.Next(cmem.Length - ints2.Length + 1);
    var skip2 = R.Rand.Next(ints2.Length - 3);
    var len2 = R.Rand.Next(1, ints2.Length - skip2 + 1);
    CMemory.Copy(ints2, skip2, cmem, skip1, len2);
    var a = cmem.SkipTake(skip1, len2);
    Debug.Assert(ints2.Skip(skip2).Take(len2).SequenceEqual(a));
    var result = cmem.ToArray();
    CMemory.Copy(ints2, 0, cmem, 1, ints2.Length);
    a = cmem.SkipTake(1, ints2.Length);
    Debug.Assert(ints2.SequenceEqual(a));
    result = cmem.ToArray();
    cmem.Dispose(); //WICHTIG

    //andere zwei auch noch prüfen.
    var cmem2 = new CMemory<int>(ints2); //size 10
    cmem = new CMemory<int>(ints1); //size 20
    ints1 = null; ints2 = null;
    skip1 = R.Rand.Next(cmem.Length - cmem2.Length + 1);
    skip2 = R.Rand.Next(cmem2.Length - 3);
    len2 = R.Rand.Next(1, cmem2.Length - skip2 + 1);
    CMemory.Copy(cmem2, skip2, cmem, skip1, len2);
    a = cmem.SkipTake(skip1, len2);
    Debug.Assert(cmem2.SkipTake(skip2, len2).SequenceEqual(a));
    result = cmem.ToArray();
    CMemory.Copy(cmem2, 0, cmem, 1, cmem2.Length);
    a = cmem.SkipTake(1, cmem2.Length);
    Debug.Assert(cmem2.Equality(a));
    result = cmem.ToArray();
    cmem.Dispose();
    cmem2.Dispose();

    ints1 = Enumerable.Range(1000, 5).ToArray();
    cmem = new CMemory<int>(ints1);
    ints2 = Enumerable.Range(10, 20).Reverse().ToArray();
    skip1 = R.Rand.Next(cmem.Length - 2);
    skip2 = R.Rand.Next(ints2.Length - cmem.Length + 1);
    len2 = R.Rand.Next(1, cmem.Length - skip1 + 1);
    CMemory.Copy(cmem, skip1, ints2, skip2, len2);
    a = cmem.SkipTake(skip1, len2);
    Debug.Assert(ints2.Skip(skip2).Take(len2).SequenceEqual(a));
    CMemory.Copy(cmem, 0, ints2, 3, cmem.Length);
    Debug.Assert(cmem.Equality(ints2.Skip(3).Take(cmem.Length).ToArray()));

    cmem.Dispose();
    cmem2.Dispose();
    Console.Write(".");
    Console.WriteLine();
  }

  private static int[] ToRngInts(int size)
  {
    var result = new int[size];
    for (var i = 0; i < result.Length; i++)
      result[i] = R.Rand.Next();
    return result;
  }

  private static char[] ToRngChars(int size)
  {
    int rng; char c;
    var cmin = char.MinValue;
    var cmax = char.MaxValue;
    var result = new char[size];
    for (var i = 0; i < result.Length; i++)
    {
      while (true)
      {
        rng = R.Rand.Next(cmin, cmax + 1);
        c = Convert.ToChar(rng);
        if (char.IsLetterOrDigit(c))
          break;
      }
      result[i] = c;
    }
    return result;
  }

  private static char ToRngChar()
  {
    int rng; char c;
    var cmin = char.MinValue;
    var cmax = char.MaxValue;
    while (true)
    {
      rng = R.Rand.Next(cmin, cmax + 1);
      c = Convert.ToChar(rng);
      if (char.IsLetterOrDigit(c))
        break;
    }
    return c;
  }

  private static bool[] ToRngBools(int size)
  {
    var result = new bool[size];
    for (var i = 0; i < result.Length; i++)
    {
      var b = R.Rand.Next(2);
      result[i] = b == 0;
    }
    return result;
  }
}

