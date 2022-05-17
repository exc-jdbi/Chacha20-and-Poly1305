

using System.Security.Cryptography;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
using static Extensions.StreamExtensions;
using static Randoms.CryptoRandom;

partial class ChaCha20
{
  /// <summary>
  /// Encrypts the plaintext and generates the authentication tag 
  /// completely in the ciphertext destination buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  /// <returns>ciphertext as array of byte</returns>
  public byte[] Encryption(byte[] plain, byte[]? associated = null)
  {
    AssertEncryption(plain, associated);
    var associat = associated is null ? RngBytes(ASSOCIATED_SIZE) : ToAssociated(associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    var result = new byte[plain.Length];
    for (var i = 0; i < result.Length; i++)
    {
      if (this.Index == 0)
      {
        //The current block always remains the same, except 
        //for the CounterIndexes, which are incremented.
        this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
        this.SetCounter();
      }
      result[i] = (byte)(this.X[this.Index] ^ plain[i]);
      this.Index = (this.Index + 1) & 63;
    }

    //iv is given to the chipher.
    var iv = FromUI32LastTwo(this.CurrentBlock);

    //Normally the 'associateddata' are not integrated into the cipher.
    //For this example project, however, I have now done so. :-)
    var precipher = iv.Concat(associat).Concat(result).ToArray();
    var cblockkey = ToCBlockKey(counterindexes);
    var tag = ToTag(cblockkey, precipher, associat);
    var cipher = tag.Concat(precipher).ToArray();
    Array.Clear(cblockkey, 0, cblockkey.Length);
    Array.Clear(precipher, 0, precipher.Length);
    Array.Clear(counterindexes, 0, counterindexes.Length);
    return cipher;
  }

  /// <summary>
  /// Encrypts the plaintext and generates the authentication tag 
  /// completely in the ciphertext destination buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt as stream.</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  /// <returns>ciphertext as stream</returns>
  public Stream Encryption(Stream plain, byte[]? associated = null)
  {
    AssertEncryption(plain, associated);

    var associat = associated is null ? RngBytes(ASSOCIATED_SIZE) : ToAssociated(associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    var stream_length = plain.Length > int.MaxValue ? int.MaxValue : (int)plain.Length;
    var msout = new MemoryStream(stream_length) { Position = TAG_SIZE };
    msout.Write(FromUI32LastTwo(this.CurrentBlock)); //set iv

    //Normally the 'associateddata' are not integrated into the cipher.
    //For this example project, however, I have now done so. :-)
    msout.Write(associat);

    int readlength;
    var result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];

    //Not the fastest variant, but it work.
    //Unmanaged is even faster.
    while ((readlength = plain.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
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

    var cblockkey = ToCBlockKey(counterindexes);
    msout.Position = TAG_SIZE;
    var tag = ToTag(cblockkey, msout, associat);
    msout.Position = 0;
    msout.Write(tag);

    return msout;
  }

  /// <summary>
  /// Encrypts the plaintext as a file and generates the authentication 
  /// tag completely into a separate file.
  /// </summary>
  /// <param name="srcfilename">Filepath source</param>
  /// <param name="destfilename">Filepath destination</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  public void Encryption(string srcfilename, string destfilename, byte[]? associated = null)
  {
    AssertEncryption(srcfilename, destfilename, associated);

    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var cipherstream = Encryption(fsinput, associated);

    if (File.Exists(destfilename)) File.Delete(destfilename);
    using var fsout = new FileStream(destfilename, FileMode.Create, FileAccess.ReadWrite);
    cipherstream.Position = 0;
    cipherstream.CopyTo(fsout);

  }

  private static byte[] ToTag(byte[] key, byte[] cipher, byte[]? entropie = null)
  {
    var bytes = entropie is not null ? entropie : key;

    if (entropie is not null)
    {
      using var _hmac = new HMACSHA512(key);
      bytes = _hmac.ComputeHash(bytes);
    }

    return ToNewKey(bytes, cipher, TAG_SIZE);
  }

  private static byte[] ToTag(byte[] key, Stream cipher, byte[]? entropie = null)
  {
    var bytes = entropie is not null ? entropie : key;

    if (entropie is not null)
    {
      using var _hmac = new HMACSHA512(key);
      bytes = _hmac.ComputeHash(bytes);
    }

    cipher.Position = TAG_SIZE;
    return ToNewKey(bytes, cipher, TAG_SIZE);
  } 

  private byte[] ToCBlockKey(uint[] counterindexes)
  {
    var cb = this.CurrentBlock.ToArray();
    cb[12] = counterindexes[0];
    cb[13] = counterindexes[1];
    return FromUI32(cb);
  }

  private static byte[] ToAssociated(byte[] associated)
  {
    //Simple and fast.
    var md5 = MD5.Create();
    var hmac = new HMACMD5(associated);
    return hmac.ComputeHash(md5.ComputeHash(associated));
  }
}





