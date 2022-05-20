


namespace exc.jdbi.Cryptography;

partial class HMacPoly1305
{
  public const int KEY_SIZE = 32;
  public const int HASH_SIZE = 16;
  private const int BLOCK_SIZE = 16;

  private int CurrentBlockOffset = 0;
  private byte[] CurrentBlock = Array.Empty<byte>();

  private uint[] R = Array.Empty<uint>();
  private uint[] S = Array.Empty<uint>();
  private uint[] K = Array.Empty<uint>();
  private uint[] H = Array.Empty<uint>();

  public bool IsDisposed { get; private set; } = false;


}
