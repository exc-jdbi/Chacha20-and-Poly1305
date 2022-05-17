using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;

namespace exc.jdbi.Randoms;
internal sealed class CryptoRandom
{
  [ThreadStatic]
  [Browsable(false)]
  [EditorBrowsable(EditorBrowsableState.Never)]
  [DebuggerBrowsable(DebuggerBrowsableState.Never)]
  [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
  private static readonly RandomNumberGenerator Rand = RandomNumberGenerator.Create();


  internal static void NextBytes(byte[] bytes)
  => Rand.GetNonZeroBytes(bytes);

  internal static int Next()
  {
    var sz = sizeof(uint);
    var bytes = new byte[sz];
    Rand.GetNonZeroBytes(bytes);
    var result = bytes[0] | (uint)(bytes[1] << 8) | (uint)(bytes[2] << 16) | (uint)(bytes[3] << 24);
    return ToI32Positive(result);
  }

  public static int Next(int max)
  => Next(0, max);

  internal static int Next(int min, int max)
  {
    if (min > max)
      throw new ArgumentOutOfRangeException(
        nameof(min), $"{nameof(min)} may not be greater than {nameof(max)}");

    if (min == max) return min;
    var sz = sizeof(uint);
    var bytes = new byte[sz];
    Rand.GetNonZeroBytes(bytes);
    var scale = bytes[0] | (uint)(bytes[1] << 8) | (uint)(bytes[2] << 16) | (uint)(bytes[3] << 24);
    return ToI32Positive((uint)(min + (max - min) * (scale / (double)(uint.MaxValue + 1.0))));
  }

  internal static byte[] RngBytes(int size)
  {
    var result = new byte[size];
    Rand.GetBytes(result);
    return result;
  }

  private static int ToI32Positive(uint number)
      => AbsI32((int)number);
  private static int AbsI32(int number)
    => number == int.MinValue ? int.MaxValue : Math.Abs(number);

  private static void WarmUp()
  {
    var bytes = new byte[4];
    var number = BitConverter.ToUInt32(bytes, 0);
    var count = (number % 1000U) + 1234U;
    bytes = new byte[count];
    Rand.GetNonZeroBytes(bytes);
  }

  static CryptoRandom()
   => WarmUp();
}