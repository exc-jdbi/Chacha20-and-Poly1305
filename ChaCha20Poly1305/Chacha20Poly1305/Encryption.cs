

namespace exc.jdbi.Cryptography;

using exc.jdbi.Extensions;
using static Converts.Convert;

partial class ChaCha20Poly1305Ex
{
  /// <summary>
  /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a same buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="aad">Additional authenticated data</param>
  /// <returns>Ciphertext as array of byte</returns>
  public byte[] Encryption(byte[] plain, byte[] aad)
  {
    //Must be traversed for a counter check.
    AssertEncryption(plain, aad);

    this.Update(aad, 0);

    int readlength, offset = 0;
    int bsize = 4 * BLOCK_SIZE;
    var poffset = TAG_SIZE + IV_SIZE;
    byte[] cblock = Array.Empty<byte>();
    byte[] result = new byte[poffset + plain.Length];
    var bufferbytes = new byte[plain.Length < bsize ? plain.Length : bsize];

    if (this.MChaCha20 is not null)
      while ((readlength = plain.ChunkReader(bufferbytes, offset, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        this.Update(bufferbytes, 0);
        Array.Copy(bufferbytes, 0, result, poffset + offset, bufferbytes.Length);

        offset += readlength;
      }
    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)plain.LongLength), 0, tmp, 8, 8);
    this.Update(tmp, 0);

    var tag = this.ToTag();
    Array.Copy(this.MIv, 0, result, TAG_SIZE, this.MIv.Length);
    Array.Copy(tag, result, tag.Length);

    return result;
  }

  /// <summary>
  /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a same buffer.
  /// </summary>
  /// <param name="plain">The content to encrypt.</param>
  /// <param name="aad">Additional authenticated data</param>
  /// <returns>Ciphertext as array of byte</returns>
  public Stream Encryption(Stream plain, byte[] aad)
  {
    //Must be traversed for a counter check.
    AssertEncryption(plain, aad);
    
    this.Update(aad, 0);

    int readlength;
    int bsize = 4 * BLOCK_SIZE;
    var offset = TAG_SIZE + IV_SIZE;
    byte[] cblock = Array.Empty<byte>();
    var bufferbytes = new byte[plain.Length < bsize ? plain.Length : bsize];
     
    var stream_length = plain.Length > int.MaxValue ? int.MaxValue : (int)plain.Length + offset;
    var msout = new MemoryStream(stream_length) { Position = offset };

    plain.Position = 0;
    if (this.MChaCha20 is not null)
      while ((readlength = plain.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        this.Update(bufferbytes, 0);
        msout.Write(bufferbytes); 
      }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)plain.Length), 0, tmp, 8, 8);
    this.Update(tmp, 0);

    msout.Position = 0;
    var tag = this.ToTag();
    msout.Write(tag);
    msout.Write(this.MIv);

    return msout;
  }

  /// <summary>
  /// Encrypts the plaintext as a file and generates the authentication 
  /// tag completely into a separate file.
  /// </summary>
  /// <param name="srcfilename">Filepath source</param>
  /// <param name="destfilename">Filepath destination</param>
  /// <param name="associated">Extra data associated with this message, which must also be provided during decryption.</param>
  public void Encryption(string srcfilename, string destfilename, byte[]aad)
  {
    this.AssertEncryption(srcfilename, destfilename, aad);

    if (File.Exists(destfilename)) File.Delete(destfilename);
    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var fsout = new FileStream(destfilename, FileMode.Create, FileAccess.ReadWrite);

    this.Update(aad, 0);

    int readlength;
    int bsize = 4 * BLOCK_SIZE;
    var offset = TAG_SIZE + IV_SIZE;
    byte[] cblock = Array.Empty<byte>();
    var bufferbytes = new byte[fsinput.Length < bsize ? fsinput.Length : bsize];

    fsinput.Position = 0;
    fsout.Position = offset;
    if (this.MChaCha20 is not null)
      while ((readlength = fsinput.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        this.Update(bufferbytes, 0);
        fsout.Write(bufferbytes);
      }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)fsinput.Length), 0, tmp, 8, 8);
    this.Update(tmp, 0);

    fsout.Position = 0;
    var tag = this.ToTag();
    fsout.Write(tag);
    fsout.Write(this.MIv);
  }

}
