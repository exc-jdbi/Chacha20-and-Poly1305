

namespace exc.jdbi.Cryptography;
partial class ChaCha20Poly1305Ex
{
  partial class ChaCha20
  {

    private static uint[] ChachaCore(int rounds, uint[] input)
    {
      var result = input.ToArray();

      for (var i = 0; i < rounds; i += 2)
      {
        QR(ref result[0], ref result[4], ref result[8], ref result[12]);
        QR(ref result[1], ref result[5], ref result[9], ref result[13]);
        QR(ref result[2], ref result[6], ref result[10], ref result[14]);
        QR(ref result[3], ref result[7], ref result[11], ref result[15]);

        QR(ref result[0], ref result[5], ref result[10], ref result[15]);
        QR(ref result[1], ref result[6], ref result[11], ref result[12]);
        QR(ref result[2], ref result[7], ref result[8], ref result[13]);
        QR(ref result[3], ref result[4], ref result[9], ref result[14]);
      }

      for (var i = 0; i < 16; ++i)
        result[i] += input[i];

      return result;
    }

    private static void QR(ref uint a, ref uint b, ref uint c, ref uint d)
    {
      a += b; d ^= a; d = RL(d, 16);
      c += d; b ^= c; b = RL(b, 12);
      a += b; d ^= a; d = RL(d, 8);
      c += d; b ^= c; b = RL(b, 7);
    }

    private static uint RL(uint x, int n)
     => (x << n) | (x >> (32 - n));
  }
}