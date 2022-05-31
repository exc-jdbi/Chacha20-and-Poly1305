


namespace exc.jdbi.Converts;
internal class Convert
{
  /// <summary>
  /// Converts four bytes to a uint-number.
  /// </summary>
  /// <param name="bytes">Requested data</param>
  /// <param name="offset">Requested offset</param>
  /// <returns>number uint</returns>
  public static uint ToUI32(byte[] bytes, int offset)
  {
    return bytes[offset]
           | (uint)bytes[offset + 1] << 8
           | (uint)bytes[offset + 2] << 16
           | (uint)bytes[offset + 3] << 24;
  }

  /// <summary>
  /// Convert 8 bytes to a ulong number.
  /// </summary>
  /// <param name="bytes">Requested data</param>
  /// <param name="offset">Requested offset</param>
  /// <returns>number ulong</returns>
  public static ulong ToUI64(byte[] bytes, int offset)
  {
    return (ulong)ToUI32(bytes, offset << 32)
                | ToUI32(bytes, offset + 4);
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
  /// Convert a ulong-number to bytes.
  /// </summary>
  /// <param name="number">Requested number</param>
  /// <returns>array of byte</returns>
  public static byte[] FromUI64(ulong number)
  {
    var bytes = new byte[8];
    FromUI64(number, bytes, 0);
    return bytes;
  }

  /// <summary>
  /// Convert a ulong-number to a bytes buffer.
  /// </summary>
  /// <param name="number">Requested number</param>
  /// <param name="bytes">Requested buffer</param>
  /// <param name="offset">Requested offset</param>

  public static void FromUI64(ulong number, byte[] bytes, int offset)
  {
    FromUI32((uint)number, bytes, offset);
    FromUI32((uint)(number >> 32), bytes, offset + 4);
  }

  /// <summary>
  /// Convert a uint-number to a bytes buffer.
  /// </summary>
  /// <param name="number">Requested number</param>
  /// <param name="bytes">Requested buffer</param>
  /// <param name="offset">Requested offset</param>
  public static void FromUI32(uint number, byte[] bytes, int offset)
  {
    bytes[offset] = (byte)number;
    bytes[offset + 1] = (byte)(number >> 8);
    bytes[offset + 2] = (byte)(number >> 16);
    bytes[offset + 3] = (byte)(number >> 24);
  }



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

  ///// <summary>
  ///// Convert four bytes to uint.
  ///// </summary>
  ///// <param name="bytes">Requested data</param>
  ///// <param name="offset">Requested offset</param>
  ///// <returns>a number uint</returns>
  //public static uint ToUI32(byte[] bytes, int offset)
  //{
  //  return bytes[offset + 0]
  //         | ((uint)bytes[offset + 1] << 8)
  //         | ((uint)bytes[offset + 2] << 16)
  //         | ((uint)bytes[offset + 3] << 24);
  //}

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

  ///// <summary>
  ///// Convert a array of uint to a array of bytes
  ///// </summary>
  ///// <param name="uints">Requested data</param>
  ///// <returns>array of bytes</returns>
  //public static byte[] FromUI32(uint[] uints)
  //{
  //  //Gibt die komplette uint-Array als Bytes zurück
  //  var offset = 0;
  //  var buffer = new byte[4];
  //  var result = new byte[uints.Length * 4];
  //  foreach (var ui32 in uints)
  //  {
  //    FromUI32(ui32, buffer, 0);
  //    Array.Copy(buffer, 0, result, offset, buffer.Length);
  //    offset += 4;
  //  }
  //  return result;
  //}

  /// <summary>
  /// Converts bytes into a uint-buffer.
  /// </summary>
  /// <param name="uints">Requested datas</param>
  /// <param name="offset">Requested offset</param>
  /// <param name="bytes">Buffer byte</param>
  public static void FromUI32(uint[] uints, int offset, byte[] bytes)
  {
    var length = bytes.Length / 4;
    for (var i = 0; i < length; i++)
      FromUI32(uints[offset + i], bytes, i * 4);
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

  public static byte[] FromUI32(uint uints)
  {
    var result = new byte[4];
    result[0] = (byte)uints;
    result[1] = (byte)(uints >> 8);
    result[2] = (byte)(uints >> 16);
    result[3] = (byte)(uints >> 24);
    return result;
  }
}
