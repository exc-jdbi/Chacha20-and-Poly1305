

namespace exc.jdbi.Cryptography;

using static Convert.Converts;
partial class XChaCha20Poly1305Ex
{
  partial class XHChaCha20
  {

    private void SetCurrentBlock(byte[] key, byte[] iv)
    {
      //Anders als bei ChaCha20 ändert sich in XChaCha20
      //der Currentblock, wenn der iv ausgetauscht wird, 
      //weil vorgängig ein HChaCha20-Key erstellt wird.
      this.ResetCurrentBlock();
      var k = HChaChaCore(key, iv, this.Rounds);
      var result = new uint[CURRENTBLOCK_SIZE]; //ctx
      result[0] = 0x61707865;
      result[1] = 0x3320646e;
      result[2] = 0x79622d32;
      result[3] = 0x6b206574;
      //Alle 32 Bytes vom HChaCha20-Key werden
      //dem Currentblock zugewiesen.
      Array.Copy(k, 0, result, 4, k.Length);
      Array.Clear(k, 0, k.Length);
      //Beide CounterIndexes werden beim Erstellen des
      //Currentblockes auf 0 gesetzt.
      //D.h. Wird ein iv-Wechsel eingeleitet, müssen
      //beide CounterIndexes übernommen werden!!
      //Siehe Zeile 58, Function SetIv(...), im Projekt
      //XChacha20
      result[12] = 0; result[13] = 0;
      //Die letzten 8 Bytes (von 24) vom iv werden
      //dem Currentblock zugewiesen.
      result[14] = ToUI32(iv, 16);
      result[15] = ToUI32(iv, 20);
      this.CurrentBlock = result;
    }

    private void ResetCurrentBlock()
    {
      if (this.CurrentBlock is not null)
        Array.Clear(this.CurrentBlock, 0, this.CurrentBlock.Length);
      this.CurrentBlock = Array.Empty<uint>();
    }


    public byte[] Next_Bytes()
    {
      this.X = FromUI32(ChachaCore(this.Rounds, this.CurrentBlock));
      this.SetCounter();
      return X.ToArray();
    }

    public uint[] Next()
    {
      var core = ChachaCore(this.Rounds, this.CurrentBlock);
      this.X = FromUI32(core);
      this.SetCounter();
      return core.ToArray();
    }


    private void SetCounter()
    {
      if (++this.CurrentBlock[12] == 0) ++this.CurrentBlock[13];
    }
  }
}
