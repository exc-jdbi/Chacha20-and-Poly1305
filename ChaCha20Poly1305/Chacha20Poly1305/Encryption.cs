

using System.Text;

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
    //https://cloud.google.com/kms/docs/additional-authenticated-data?hl=de

    //Must be traversed for a counter check.
    AssertEncryption(plain, aad);

    this.Update(aad);

    int readlength, offset = 0;
    int bsize = 4 * BLOCK_SIZE;
    var poffset = HASH_SIZE + IV_SIZE;
    byte[] cblock = Array.Empty<byte>();
    byte[] result = new byte[poffset + plain.Length];
    var bufferbytes = new byte[plain.Length < bsize ? plain.Length : bsize];

    while ((readlength = plain.ChunkReader(bufferbytes, offset, bufferbytes.Length)) != 0)
    {
      if (readlength != bufferbytes.Length)
        Array.Resize(ref bufferbytes, readlength);

      if (this.MChaCha20 is not null)
        cblock = this.MChaCha20.Next_Bytes();

      for (int i = 0; i < readlength; i++)
        bufferbytes[i] ^= cblock[i];

      this.Update(bufferbytes);
      Array.Copy(bufferbytes, 0, result, poffset + offset, bufferbytes.Length);

      offset += readlength;
    }
    Array.Clear(cblock, 0, cblock.Length);
    Array.Clear(bufferbytes, 0, bufferbytes.Length);

    var tmp = new byte[16];
    Array.Copy(FromUI64((ulong)aad.LongLength), tmp, 8);
    Array.Copy(FromUI64((ulong)plain.LongLength), 0, tmp, 8, 8);
    this.Update(tmp);

    var tag = this.ToTag();
    Array.Copy(this.MIv, 0, result, TAG_SIZE, this.MIv.Length);
    Array.Copy(tag, result, tag.Length);

    return result;
  }
}
