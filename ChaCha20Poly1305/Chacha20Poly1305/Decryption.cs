
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

    this.Update(aad,0);
    this.Update(cipher, offset);
    long realcipherlength = cipher.Length - offset;

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)realcipherlength), 0, tmp, 8, 8);
    this.Update(tmp,0);
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

  private void Verify(byte[] cipher)
  {
    var verify = cipher.Take(TAG_SIZE).SequenceEqual(this.ToTag());
    if (verify) return;
    throw new CryptographicException(
      $"Signature verification has failed!");
  }
}
