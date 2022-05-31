
using System.Security.Cryptography;

namespace exc.jdbi.Cryptography;

using static Convert.Converts;
using static Extensions.StreamExtensions;

partial class XChaCha20
{
  /// <summary> 
  /// Decrypts the ciphertext into the provided destination 
  /// buffer if the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt.</param>
  /// <param name="associated">Extra data associated with this message, which must match the value provided during encryption.</param>
  /// <returns>plaintext as array of bytes</returns>
  public byte[] Decryption(byte[] cipher, byte[]? associated = null)
  {
    this.AssertDecryption(cipher);

    var iv = cipher.Skip(TAG_SIZE).Take(IV_SIZE).ToArray();
    this.SetIv(iv);

    var associat = this.ToAssociated(associated);
    var cblockkey = FromUI32(this.CurrentBlock);
    Verify(cblockkey, cipher, associat);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);

    var offset = TAG_SIZE + IV_SIZE;
    var result = new byte[cipher.Length - offset];
    for (var i = 0; i < result.Length; i++)
    {
      if (this.Index == 0)
      {
        this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
        this.SetCounter();
      }
      result[i] = (byte)(this.X[this.Index] ^ cipher[i + offset]);
      this.Index = (this.Index + 1) & 63;
    }
    return result;
  }

  /// <summary>
  /// Decrypts the ciphertext into the provided destination 
  /// stream if the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt as stream.</param>
  /// <param name="associated">Extra data associated with this message, which must match the value provided during encryption.</param>
  /// <returns>plaintext as stream</returns>
  public Stream Decryption(Stream cipher, byte[]? associated = null)
  {
    this.AssertDecryption(cipher);

    cipher.Position = TAG_SIZE;
    var result = new byte[IV_SIZE];
    cipher.ChunkReader(result, 0, result.Length);

    this.SetIv(result);
    var associat = this.ToAssociated(associated);
    var cblockkey = FromUI32(this.CurrentBlock);
    Verify(cblockkey, cipher, associat);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);

    int readlength;
    Array.Clear(result, 0, result.Length);
    result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];

    var skip = TAG_SIZE + IV_SIZE;
    cipher.Position = skip;

    var stream_length = cipher.Length - skip > int.MaxValue ? int.MaxValue : (int)cipher.Length - skip;
    var msout = new MemoryStream(stream_length);

    while ((readlength = cipher.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
    {
      if (result.Length != readlength)
        result = new byte[readlength];

      for (var i = 0; i < readlength; i++)
      {
        if (this.Index == 0)
        {
          //The current block always remains the same, except 
          //for the CounterIndexes, which are incremented.
          this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
          this.SetCounter();
        }
        result[i] = (byte)(this.X[this.Index] ^ bufferbytes[i]);
        this.Index = (this.Index + 1) & 63;
      }
      msout.Write(result);
    }
    return msout;
  }

  /// <summary>
  /// Decrypts the ciphertext into the provided destination 
  /// file if the authentication tag can be validated.
  /// </summary>
  /// <param name="srcfilename">Filepath source.</param>
  /// <param name="destfilename">Filepath destination.</param>
  /// <param name="associated">Extra data associated with this message, which must match the value provided during encryption.</param>
  public void Decryption(string srcfilename, string destfilename, byte[]? associated = null)
  {
    this.AssertDecryption(srcfilename, destfilename);

    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var fsout = new FileStream(destfilename, FileMode.CreateNew, FileAccess.ReadWrite);

    fsinput.Position = TAG_SIZE;
    var result = new byte[IV_SIZE];
    fsinput.ChunkReader(result, 0, result.Length);

    this.SetIv(result);
    var associat = this.ToAssociated(associated);
    var cblockkey = FromUI32(this.CurrentBlock);
    Verify(cblockkey, fsinput, associat);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);

    int readlength;
    Array.Clear(result, 0, result.Length);
    result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];

    var skip = TAG_SIZE + IV_SIZE;
    fsinput.Position = skip;

    while ((readlength = fsinput.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
    {
      if (result.Length != readlength)
        result = new byte[readlength];

      for (var i = 0; i < readlength; i++)
      {
        if (this.Index == 0)
        {
          //The current block always remains the same, except 
          //for the CounterIndexes, which are incremented.
          this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
          this.SetCounter();
        }
        result[i] = (byte)(this.X[this.Index] ^ bufferbytes[i]);
        this.Index = (this.Index + 1) & 63;
      }
      fsout.Write(result);
    }
  }

  private static void Verify(byte[] key, byte[] cipher, byte[] associat)
  {
    var expect = cipher.Take(TAG_SIZE).ToArray();
    var tag = ToTag(key, cipher, TAG_SIZE, associat);
    var verify = tag.SequenceEqual(expect);
    Array.Clear(tag, 0, tag.Length);
    if (verify) return;

    throw new CryptographicException(
      $"Tag-Signature verification has failed!");
  }


  private static void Verify(byte[] key, Stream cipher, byte[] associat)
  {
    cipher.Position = 0;
    var expect = new byte[TAG_SIZE];
    cipher.ChunkReader(expect, 0, expect.Length);

    cipher.Position = TAG_SIZE;
    var tag = ToTag(key, cipher, associat);
    var verify = tag.SequenceEqual(expect);
    Array.Clear(tag, 0, tag.Length);
    if (verify) return;

    throw new CryptographicException(
      $"Tag-Signature verification has failed!");
  }
}
