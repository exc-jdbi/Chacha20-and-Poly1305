

using System.Security.Cryptography;
using System.Text;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
using static Extensions.StreamExtensions;

partial class ChaCha20
{

  /// <summary>
  /// Encrypts the plaintext and generates the authentication tag 
  /// completely in the ciphertext destination buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="associated">
  /// Extra data associated with this message, which must 
  /// also be provided during decryption.
  /// </param>
  /// <returns>ciphertext as array of byte</returns>
  public byte[] Encryption(byte[] plain, byte[]? associated = null)
  {
    this.AssertEncryption(plain, associated);
    var associat = this.ToAssociated(associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    var offset = TAG_SIZE + IV_SIZE;
    var result = new byte[plain.Length + offset];
    for (var i = 0; i < result.Length - offset; i++)
    {
      if (this.Index == 0)
      {
        //The current block always remains the same, except 
        //for the CounterIndexes, which are incremented.
        this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
        this.SetCounter();
      }
      result[i + offset] = (byte)(this.X[this.Index] ^ plain[i]);
      this.Index = (this.Index + 1) & 63;
    }

    //iv is given to the cipher.
    var iv = FromUI32LastTwo(this.CurrentBlock);
    Array.Copy(iv, 0, result, TAG_SIZE, iv.Length);

    var cblockkey = this.ToCBlockKey(counterindexes);
    var tag = ToTag(cblockkey, result, TAG_SIZE, associat);
    Array.Copy(tag, result, tag.Length);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);
    Array.Clear(counterindexes, 0, counterindexes.Length);

    return result;
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
    this.AssertEncryption(plain, associated);

    var associat = this.ToAssociated(associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    var stream_length = plain.Length > int.MaxValue ? int.MaxValue : (int)plain.Length;
    var msout = new MemoryStream(stream_length) { Position = TAG_SIZE };
    msout.Write(FromUI32LastTwo(this.CurrentBlock)); //set iv

    int readlength;
    var result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];

    //Not the fastest variant, but it work. 
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

    var cblockkey = this.ToCBlockKey(counterindexes);
    msout.Position = TAG_SIZE;
    var tag = ToTag(cblockkey, msout, associat);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);
    Array.Clear(counterindexes, 0, counterindexes.Length);

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
    this.AssertEncryption(srcfilename, destfilename, associated);
     
    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read); 
    using var fsout = new FileStream(destfilename, FileMode.CreateNew, FileAccess.ReadWrite);

    var associat = this.ToAssociated(associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    var stream_length = fsinput.Length > int.MaxValue ? int.MaxValue : (int)fsinput.Length;
    fsout.Position = TAG_SIZE;
    fsout.Write(FromUI32LastTwo(this.CurrentBlock)); //set iv

    int readlength;
    var result = Array.Empty<byte>();
    var bufferbytes = new byte[BLOCK_SIZE];

    //Not the fastest variant, but it work. 
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

    var cblockkey = this.ToCBlockKey(counterindexes);
    fsout.Position = TAG_SIZE;
    var tag = ToTag(cblockkey, fsout, associat);
    Array.Clear(associat, 0, associat.Length);
    Array.Clear(cblockkey, 0, cblockkey.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);
    Array.Clear(counterindexes, 0, counterindexes.Length);

    fsout.Position = 0;
    fsout.Write(tag);
  }

  private static byte[] ToTag(byte[] key, byte[] cipher, int offset, byte[]? entropie = null)
  {
    var bytes = entropie is not null ? entropie : key;

    if (entropie is not null)
    {
      using var _hmac = new HMACSHA512(key);
      bytes = _hmac.ComputeHash(bytes);
    }
    return ToNewKey(bytes, cipher, offset, TAG_SIZE);
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
    var result = FromUI32(cb);
    Array.Clear(cb, 0, cb.Length);
    return result;
  }

  private byte[] ToAssociated(byte[]? associated)
  {
    //Simple and fast. Return Length = 16.
    var k = FromUI32(this.CurrentBlock);
    var associat = associated is null ? ToAssociated() : associated;

    using var md5 = MD5.Create();
    using var hmac = new HMACMD5(k);
    var result = hmac.ComputeHash(md5.ComputeHash(associat));
    Array.Clear(k, 0, k.Length);
    return result;
  }

  private static byte[] ToAssociated()
  => Encoding.UTF8.GetBytes("ChaCha20 from D.J. Bernstein.");

}





