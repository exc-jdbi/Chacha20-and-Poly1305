

namespace exc.jdbi.Converts;

/// <summary>
/// Includes various conversion tools
/// </summary>
internal sealed partial class Convert
{
  /// <summary>
  /// Converts Bytes to a array of uint.
  /// </summary>
  /// <param name="bytes">Requested data.</param>
  /// <param name="offset">Requested offset</param>
  /// <param name="size">Requested size</param>
  /// <returns>Array of uint</returns>
  public static uint[] ToUI32s(byte[] bytes, int offset, int size)
  {
    var result = new uint[size];
    for (var i = 0; i < result.Length; i++)
    {
      result[i] = ToUI32(bytes, offset);
      offset += 4;
    }
    return result;
  }

  /// <summary>
  /// Convert four bytes to uint.
  /// </summary>
  /// <param name="bytes">Requested data</param>
  /// <param name="offset">Requested offset</param>
  /// <returns>a number uint</returns>
  public static uint ToUI32(byte[] bytes, int offset)
  {
    return bytes[offset + 0]
           | ((uint)bytes[offset + 1] << 8)
           | ((uint)bytes[offset + 2] << 16)
           | ((uint)bytes[offset + 3] << 24);
  }

  /// <summary>
  /// Converts bytes into a uint-buffer.
  /// </summary>
  /// <param name="bytes">Requested data</param>
  /// <param name="boffset">Requested byte-offset</param>
  /// <param name="uints">Buffer uint</param>
  /// <param name="uioffset">Requested uint-data</param>
  /// <param name="size">Requested size</param>
  public static void ToUI32s(byte[] bytes, int boffset, uint[] uints, int uioffset, int size)
  {
    for (var i = 0; i < size; ++i)
    {
      uints[uioffset + i] = ToUI32(bytes, boffset);
      boffset += 4;
    }
  }

  /// <summary>
  /// Convert a array of uint to a array of bytes
  /// </summary>
  /// <param name="uints">Requested data</param>
  /// <returns>array of bytes</returns>
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
  /// Converts bytes into a uint-buffer.
  /// </summary>
  /// <param name="uints">Requested data</param>
  /// <param name="bytes">Buffer byte</param>
  /// <param name="offset">Requested offset</param>
  public static void FromUI32(uint uints, byte[] bytes, int offset)
  {
    bytes[offset] = (byte)uints;
    bytes[offset + 1] = (byte)(uints >> 8);
    bytes[offset + 2] = (byte)(uints >> 16);
    bytes[offset + 3] = (byte)(uints >> 24);
  }

  /// <summary>
  /// Converts the last two uint-values into a byte array.
  /// </summary>
  /// <param name="uints">Requested data</param>
  /// <returns>array of byte</returns>
  public static byte[] FromUI32LastTwo(uint[] uints)
  {
    var result = new byte[8];
    FromUI32(uints[^2], result, 0);
    FromUI32(uints[^1], result, 4);
    return result;
  }

}
