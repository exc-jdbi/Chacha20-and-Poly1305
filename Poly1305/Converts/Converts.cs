


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
}
