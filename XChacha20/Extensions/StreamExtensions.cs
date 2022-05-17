

namespace exc.jdbi.Extensions;
internal static class StreamExtensions
{
  /// <summary>
  /// Takes a sequence and puts into the buffer. 
  /// </summary>
  /// <param name="stream">Requested stream</param>
  /// <param name="data">Requested buffer</param>
  /// <param name="offset">Requested offset</param>
  /// <param name="length">Requested length</param>
  /// <returns>Number of read</returns>
  internal static int ChunkReader(
       this Stream stream,
       byte[] data,
       int offset,
       int length)
  {

    int read;
    int remaining = data.Length;
    while (remaining > 0 &&
      (read = stream.Read(data, offset, remaining)) != 0)
    {
      remaining -= read;
      offset += read;
    }
    return length - remaining;
  }
}
