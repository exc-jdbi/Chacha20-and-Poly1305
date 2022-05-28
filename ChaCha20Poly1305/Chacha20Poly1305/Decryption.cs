
using System.Security.Cryptography;

namespace exc.jdbi.Cryptography;

using static Converts.Convert;
using static Extensions.StreamExtensions;

partial class ChaCha20Poly1305Ex
{
  /// <summary>
  /// Decrypts the ciphertext into the provided destination buffer if 
  /// the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt.</param>
  /// <param name="aad">Additional authenticated data</param>
  /// <returns>Plaintext as array of byte</returns>
  public byte[] Decryption(byte[] cipher, byte[] aad)
  {
    AssertDecryption(cipher);

    var offset = TAG_SIZE + IV_SIZE;
    var iv = cipher.Skip(TAG_SIZE).Take(IV_SIZE).ToArray();
    if (!iv.SequenceEqual(this.MIv))
      this.NewInit(this.MKey.ToArray(), iv);

    this.Update(aad, 0);
    this.Update(cipher, offset);
    long realcipherlength = cipher.Length - offset;

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)realcipherlength), 0, tmp, 8, 8);
    this.Update(tmp, 0);
    Verify(cipher);

    int bsize = 4 * BLOCK_SIZE;
    int readlength, roffset = 0;
    byte[] cblock = Array.Empty<byte>();
    byte[] result = new byte[realcipherlength];
    var bufferbytes = new byte[realcipherlength < bsize ? realcipherlength : bsize];

    if (this.MChaCha20 is not null)
      while ((readlength = cipher.ChunkReader(bufferbytes, offset, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        Array.Copy(bufferbytes, 0, result, roffset, bufferbytes.Length);
        roffset += readlength;
        offset += readlength;
      }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    return result;
  }

  /// <summary>
  /// Decrypts the ciphertext into the provided destination buffer if 
  /// the authentication tag can be validated.
  /// </summary>
  /// <param name="cipher">The encrypted content to decrypt.</param>
  /// <param name="aad">Additional authenticated data</param>
  /// <returns>Plaintext as array of byte</returns>
  public Stream Decryption(Stream cipher, byte[] aad)
  {
    AssertDecryption(cipher);

    var offset = TAG_SIZE + IV_SIZE;
    var iv = new byte[IV_SIZE];
    cipher.Position = TAG_SIZE;
    cipher.Read(iv);

    if (!iv.SequenceEqual(this.MIv))
      this.NewInit(this.MKey.ToArray(), iv);
     
    this.Update(aad, 0);
    this.Update(cipher, offset);
    long realcipherlength = cipher.Length - offset;

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)realcipherlength), 0, tmp, 8, 8);
    this.Update(tmp, 0);
    Verify(cipher, 0);

    int readlength;
    int bsize = 4 * BLOCK_SIZE;
    byte[] cblock = Array.Empty<byte>();
    var bufferbytes = new byte[realcipherlength < bsize ? realcipherlength : bsize];

    var stream_length = cipher.Length - offset > int.MaxValue ? int.MaxValue : (int)cipher.Length - offset;
    var msout = new MemoryStream(stream_length);

    cipher.Position = offset;
    if (this.MChaCha20 is not null)
      while ((readlength = cipher.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        msout.Write(bufferbytes);
      }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    return msout;
  }

  /// <summary> 
  /// Decrypts the ciphertext into the provided destination 
  /// file if the authentication tag can be validated.
  /// </summary>
  /// <param name="srcfilename">Filepath source.</param>
  /// <param name="destfilename">Filepath destination.</param>
  /// <param name="associated">Extra data associated with this message, which must match the value provided during encryption.</param>
  public void Decryption(string srcfilename, string destfilename, byte[] aad)
  {
    this.AssertDecryption(srcfilename, destfilename);

    if (File.Exists(destfilename)) File.Delete(destfilename);
    using var fsinput = new FileStream(srcfilename, FileMode.Open, FileAccess.Read);
    using var fsout = new FileStream(destfilename, FileMode.Create, FileAccess.ReadWrite);

    var offset = TAG_SIZE + IV_SIZE;
    var iv = new byte[IV_SIZE];
    fsinput.Position = TAG_SIZE;
    fsinput.Read(iv);

    if (!iv.SequenceEqual(this.MIv))
      this.NewInit(this.MKey.ToArray(), iv);

    this.Update(aad, 0);
    this.Update(fsinput, offset);
    long realcipherlength = fsinput.Length - offset;

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)realcipherlength), 0, tmp, 8, 8);
    this.Update(tmp, 0);
    Verify(fsinput, 0);

    int readlength;
    int bsize = 4 * BLOCK_SIZE;
    byte[] cblock = Array.Empty<byte>();
    var bufferbytes = new byte[realcipherlength < bsize ? realcipherlength : bsize];

    fsout.Position = 0;
    fsinput.Position = offset;
    if (this.MChaCha20 is not null)
      while ((readlength = fsinput.ChunkReader(bufferbytes, 0, bufferbytes.Length)) != 0)
      {
        if (readlength != bufferbytes.Length)
          Array.Resize(ref bufferbytes, readlength);

        cblock = this.MChaCha20.Next_Bytes();

        for (int i = 0; i < readlength; i++)
          bufferbytes[i] ^= cblock[i];

        fsout.Write(bufferbytes);
      }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);
  }

  private void Verify(byte[] cipher)
  {
    var verify = cipher.Take(TAG_SIZE).SequenceEqual(this.ToTag());
    if (verify) return;
    throw new CryptographicException(
      $"Signature verification has failed!");
  }

  private void Verify(Stream cipher, long start)
  {
    cipher.Position = start;
    var expect = new byte[TAG_SIZE];
    cipher.Read(expect);
    var verify = expect.SequenceEqual(this.ToTag());
    if (verify) return;
    throw new CryptographicException(
      $"Signature verification has failed!");
  }
}
