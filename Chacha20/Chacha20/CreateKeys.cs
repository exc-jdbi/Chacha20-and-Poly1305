
using System.Security.Cryptography;

namespace exc.jdbi.Cryptography;


partial class ChaCha20
{

  private static byte[] ToNewKey(byte[] key, byte[] bytes, int size)
  {
    if (size < 8 || size > 64)
      throw new ArgumentOutOfRangeException(nameof(size),
        $"{nameof(size)} >= 8 and  {nameof(size)} <= 64");
    using var hmac = new HMACSHA512(key);
    var hash = hmac.ComputeHash(bytes);
    if (size == 64) return hash;
    if (size == 63) return hash.Skip(1).ToArray();
    var start = (hash.Sum(x => x) % (64 - size - 1)) + 1;
    return hash.Skip(start).Take(size).ToArray();
  }

  private static byte[] ToNewKey(byte[] key, Stream bytes, int size)
  {
    if (size < 8 || size > 64)
      throw new ArgumentOutOfRangeException(nameof(size),
        $"{nameof(size)} >= 8 and  {nameof(size)} <= 64");
    using var hmac = new HMACSHA512(key);
    var hash = hmac.ComputeHash(bytes);
    if (size == 64) return hash;
    if (size == 63) return hash.Skip(1).ToArray();
    var start = (hash.Sum(x => x) % (64 - size - 1)) + 1;
    return hash.Skip(start).Take(size).ToArray();
  }

}