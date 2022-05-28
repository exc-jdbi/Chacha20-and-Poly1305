
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

    var iv = cipher.Skip(TAG_SIZE).Take(IV_SIZE).ToArray();
    if (!iv.SequenceEqual(this.MIv))
      this.NewInit(this.MKey.ToArray(), iv);

    var realcipher = cipher.Skip(TAG_SIZE + IV_SIZE).ToArray();
    this.Update(aad);
    this.Update(realcipher);

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)realcipher.LongLength), 0, tmp, 8, 8);
    this.Update(tmp);
    Verify(cipher);

    int readlength, offset = 0;
    int bsize = 4 * BLOCK_SIZE;
    byte[] cblock = Array.Empty<byte>();
    byte[] result = new byte[realcipher.Length];
    var bufferbytes = new byte[realcipher.Length < bsize ? realcipher.Length : bsize];

    while ((readlength = realcipher.ChunkReader(bufferbytes, offset, bufferbytes.Length)) != 0)
    {
      if (readlength != bufferbytes.Length)
        Array.Resize(ref bufferbytes, readlength);

      if (this.MChaCha20 is not null)
        cblock = this.MChaCha20.Next_Bytes();

      for (int i = 0; i < readlength; i++)
        bufferbytes[i] ^= cblock[i];
       
      Array.Copy(bufferbytes, 0, result, offset, bufferbytes.Length);
      offset += readlength;
    }

    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    return result;
  }

  private void Verify(byte[]cipher)
  {
    var verify = cipher.Take(TAG_SIZE).SequenceEqual(this.ToTag());
    if (verify) return;
    throw new CryptographicException(
      $"Signature verification has failed!");
  }
}
