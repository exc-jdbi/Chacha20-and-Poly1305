

namespace exc.jdbi.Convert;


internal partial class Converts
{
  /// <summary>
  /// Converts four bytes to a number uint.
  /// </summary>
  /// <param name="bytes">Requested data</param>
  /// <param name="offset">Requested offset</param>
  /// <returns></returns>
  public static uint ToUI32(byte[] bytes, int offset)
  {
    return bytes[offset + 0]
           | ((uint)bytes[offset + 1] << 8)
           | ((uint)bytes[offset + 2] << 16)
           | ((uint)bytes[offset + 3] << 24);
  }

  /// <summary>
  /// Converts a Array of uint to a Array of byte.
  /// </summary>
  /// <param name="uints">Requested data</param>
  /// <returns></returns>
  public static byte[] FromUI32(uint[] uints)
  {
    //Gibt die komplette uint-Array als Bytes zurück
    var offset = 0;
    var buffer = new byte[4];
    var result = new byte[uints.Length * 4];
    foreach (var ui32 in uints)
    {
      FromUI32(ui32, buffer, 0);
      Array.Copy(buffer, 0, result, offset, buffer.Length);
      offset += 4;
    }
    return result;
  }

  /// <summary>
  /// Convert e number uint to a byte buffer.
  /// </summary>
  /// <param name="uints">Requested data</param>
  /// <param name="bytes">Requested buffer</param>
  /// <param name="offset">Requested offset</param>
  public static void FromUI32(uint uints, byte[] bytes, int offset)
  {
    bytes[offset] = (byte)uints;
    bytes[offset + 1] = (byte)(uints >> 8);
    bytes[offset + 2] = (byte)(uints >> 16);
    bytes[offset + 3] = (byte)(uints >> 24);
  }

}
