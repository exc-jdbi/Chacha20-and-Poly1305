

using System.Security.Cryptography;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
using static Extensions.StreamExtensions;

partial class ChaCha20
{
  /// <summary>
  /// Decrypts the ciphertext into the provided destination 
  /// buffer if the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt.</param>
  /// <returns>plaintext as array of bytes</returns>
  public byte[] Decryption(byte[] cipher)
  {
    AssertDecryption(cipher);
    var iv = cipher.Skip(TAG_SIZE).Take(IV_SIZE).ToArray();
    ToUI32s(iv, 0, this.CurrentBlock, 14, 2);
    var cblockkey = FromUI32(this.CurrentBlock);

    Verify(cblockkey, cipher);
    var realcipher = cipher.Skip(TAG_SIZE + ASSOCIATED_SIZE + IV_SIZE).ToArray();

    var result = new byte[realcipher.Length];
    for (var i = 0; i < result.Length; i++)
    {
      if (this.Index == 0)
      {
        this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
        this.SetCounter();
      }
      result[i] = (byte)(this.X[this.Index] ^ realcipher[i]);
      this.Index = (this.Index + 1) & 63;
    }
    return result;
  }

  /// <summary>
  /// Decrypts the ciphertext into the provided destination 
  /// stream if the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt as stream.</param>
  /// <returns>plaintext as stream</returns>
  public Stream Decryption(Stream cipher)
  {
    AssertDecryption(cipher);

    cipher.Position = TAG_SIZE;
    var result = new byte[IV_SIZE];
    cipher.ChunkReader(result, 0, result.Length);
    ToUI32s(result, 0, this.CurrentBlock, 14, 2);
    var cblockkey = FromUI32(this.CurrentBlock);

    Verify(cblockkey, cipher);

    int readlength;
    Array.Clear(result, 0, result.Length);
    result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];
    cipher.Position = TAG_SIZE + ASSOCIATED_SIZE + IV_SIZE;

    var skip = TAG_SIZE + ASSOCIATED_SIZE + IV_SIZE;
    var stream_length = cipher.Length - skip > int.MaxValue ? int.MaxValue : (int)cipher.Length - skip;
    var msout = new MemoryStream(stream_length) /*{ Position = TAG_SIZE }*/;

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
  public void Decryption(string srcfilename, string destfilename)
  {
    AssertDecryption(srcfilename, destfilename);

    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var decipherstream = Decryption(fsinput);

    if (File.Exists(destfilename)) File.Delete(destfilename);
    //using var fsout = new FileStream(destfilename, FileMode.Create, FileAccess.Write, FileShare.Delete);
    using var fsout = new FileStream(destfilename, FileMode.Create, FileAccess.ReadWrite);
    decipherstream.Position = 0;
    decipherstream.CopyTo(fsout);
  }

  private static void Verify(byte[] key, byte[] cipher)
  {
    var tag = cipher.Take(TAG_SIZE).ToArray();
    var iv = cipher.Skip(TAG_SIZE).Take(IV_SIZE).ToArray();
    var associat = cipher.Skip(TAG_SIZE + IV_SIZE).Take(ASSOCIATED_SIZE).ToArray();
    var realcipher = cipher.Skip(TAG_SIZE + ASSOCIATED_SIZE + IV_SIZE).ToArray();
    var testcipher = iv.Concat(associat).Concat(realcipher).ToArray();

    var verify = ToTag(key, testcipher, associat).SequenceEqual(tag);
    Array.Clear(iv, 0, iv.Length);
    Array.Clear(tag, 0, tag.Length);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(realcipher, 0, realcipher.Length);
    Array.Clear(testcipher, 0, testcipher.Length);
    if (verify) return;

    throw new CryptographicException(
      $"Signature verification has failed!");
  }

  private static void Verify(byte[] key, Stream cipher)
  {
    cipher.Position = 0;
    var tag = new byte[TAG_SIZE];
    var associat = new byte[ASSOCIATED_SIZE];
    cipher.ChunkReader(tag, 0, tag.Length);
    cipher.Position = TAG_SIZE + IV_SIZE;
    cipher.ChunkReader(associat, 0, associat.Length);

    cipher.Position = TAG_SIZE;
    var verify = ToTag(key, cipher, associat).SequenceEqual(tag);
    Array.Clear(tag, 0, tag.Length);
    Array.Clear(associat, 0, associat.Length);
    if (verify) return;

    throw new CryptographicException(
      $"Signature verification has failed!");
  }

}