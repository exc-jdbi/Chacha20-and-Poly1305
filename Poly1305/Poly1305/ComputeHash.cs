
namespace exc.jdbi.Cryptography;

partial class Poly1305
{
  /// <summary>
  /// Computes the hash value for the specified byte array.
  /// </summary>
  /// <param name="bytes">The input to compute the hash code for.</param>
  /// <returns>The computed hash code.</returns>
  public byte[] ComputeHash(byte[] bytes)
  {
    this.UpdateBlock(bytes);
    return this.DoFinal();
  }

  /// <summary>
  /// Computes the hash value for the specified Stream object.
  /// </summary>
  /// <param name="streambytes">The input to compute the hash code for.</param>
  /// <returns>The computed hash code.</returns>
  public byte[] ComputeHash(Stream streambytes)
  {
    int readlength;
    var bufferbytes = new byte[BLOCK_SIZE];

    while ((readlength = streambytes.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
    {
      if (this.CurrentBlockOffset == BLOCK_SIZE)
      {
        this.ProcessBlock();
        this.CurrentBlockOffset = 0;
      }

      var tocopy = Math.Min(readlength, BLOCK_SIZE - this.CurrentBlockOffset);
      Array.Copy(bufferbytes, 0, this.CurrentBlock, this.CurrentBlockOffset, tocopy);
      this.CurrentBlockOffset += tocopy;
    }

    return this.DoFinal();
  }

}
