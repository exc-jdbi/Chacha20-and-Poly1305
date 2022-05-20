
using System.Security.Cryptography;
using System.Text;

namespace exc.jdbi.Cryptography;

using static Convert.Converts;
using static Extensions.StreamExtensions;

partial class XChaCha20
{

  /// <summary>
  /// Encrypts the plaintext and generates the authentication tag 
  /// completely in the ciphertext destination buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  /// <param name="new_iv">Yes, if generated a new iv (nonce), otherwise no.</param>
  /// <returns>ciphertext as array of byte</returns>
  public byte[] Encryption(byte[] plain, byte[]? associated = null, bool new_iv = false)
  {
    this.AssertEncryption(plain, associated);
    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    if (new_iv) this.SetIv(NewIv());
    var associat = this.ToAssociated(associated);

    var offset = TAG_SIZE + IV_SIZE;
    var result = new byte[plain.Length + offset];
    for (var i = 0; i < result.Length - offset; i++)
    {
      if (this.Index == 0)
      {
        this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
        this.SetCounter();
      }
      result[i + offset] = (byte)(this.X[this.Index] ^ plain[i]);
      this.Index = (this.Index + 1) & 63;
    }

    Array.Copy(this.MIv, 0, result, TAG_SIZE, this.MIv.Length);
    var cblockkey = this.ToCBlockKey(counterindexes);
    var tag = ToTag(cblockkey, result, TAG_SIZE, associat);

    Array.Copy(tag, result, tag.Length);
    return result;

  }

  /// <summary>
  /// Encrypts the plaintext and generates the authentication tag 
  /// completely in the ciphertext destination stream.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  /// <param name="new_iv">Yes, if generated a new iv (nonce), otherwise no.</param>
  /// <returns>ciphertext as stream</returns>
  public Stream Encryption(Stream plain, byte[]? associated = null, bool new_iv = false)
  {
    this.AssertEncryption(plain, associated);

    var counterindexes = new[] { this.CurrentBlock[12], this.CurrentBlock[13] };

    if (new_iv) this.SetIv(NewIv());
    var associat = this.ToAssociated(associated);

    var stream_length = plain.Length > int.MaxValue ? int.MaxValue : (int)plain.Length;
    var msout = new MemoryStream(stream_length) { Position = TAG_SIZE };
    msout.Write(this.MIv);

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
          //The CurrentBlock always remains the same, except 
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
    msout.Position = 0;
    msout.Write(tag);
    return msout;
  }

  /// <summary>
  /// Encrypts the plaintext from a file and generates the authentication tag 
  /// completely in the ciphertext destination file.
  /// </summary>
  /// <param name="srcfilename">Required source.</param>
  /// <param name="destfilename">Required destination.</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  /// <param name="new_iv">Yes, if generated a new iv (nonce), otherwise no.</param>
  public void Encryption(string srcfilename, string destfilename, byte[]? associated = null, bool new_iv = false)
  {
    this.AssertEncryption(srcfilename, destfilename, associated);

    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var cipherstream = this.Encryption(fsinput, associated, new_iv);

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
    return FromUI32(cb);
  }

  private byte[] ToAssociated(byte[]? associated)
  {
    //Simple and fast. Return Length = 16.
    var k = FromUI32(this.CurrentBlock.ToArray());
    var associat = associated is null ? ToAssociated() : associated;

    using var md5 = MD5.Create();
    using var hmac = new HMACMD5(k);
    return hmac.ComputeHash(md5.ComputeHash(associat));
  }

  private static byte[] ToAssociated()
  => Encoding.UTF8.GetBytes("Modified ChaCha20 from D.J. Berstein.");


}
