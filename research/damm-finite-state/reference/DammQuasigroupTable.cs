// Ignore Spelling: Damm, Quasigroup

namespace CheckDigits.Net.Utility;

/// <summary>
///   Precomputed Damm algorithm quasigroup table entries.
/// </summary>
public sealed class DammQuasigroupTable : ITwoDimensionalLookupTable
{
   // 2D array flattened to 1D. Gives ~30% performance improvement vs 2D.
   private static readonly Int32[] _quasigroupTable =
   [
      0, 3, 1, 7, 5, 9, 8, 6, 4, 2,
      7, 0, 9, 2, 1, 5, 4, 8, 6, 3,
      4, 2, 0, 6, 8, 7, 1, 3, 5, 9,
      1, 7, 5, 0, 9, 8, 3, 4, 2, 6,
      6, 1, 2, 3, 0, 4, 5, 9, 7, 8,
      3, 6, 7, 4, 2, 0, 9, 5, 8, 1,
      5, 8, 6, 9, 7, 2, 0, 1, 3, 4,
      8, 9, 4, 5, 3, 6, 2, 0, 1, 7,
      9, 4, 3, 8, 6, 1, 7, 2, 0, 5,
      2, 5, 8, 1, 4, 3, 6, 7, 9, 0,
   ];

   private static readonly Lazy<DammQuasigroupTable> _lazy
      = new(() => new DammQuasigroupTable());

   // Force singleton.
   private DammQuasigroupTable() { }

   /// <summary>
   ///   Reference to the single instance of the 
   ///   <see cref="DammQuasigroupTable"/>
   /// </summary>
   public static DammQuasigroupTable Instance => _lazy.Value;

   /// <inheritdoc/>
   public Int32 this[Int32 x, Int32 y] => _quasigroupTable[(x * 10) + y];
}
