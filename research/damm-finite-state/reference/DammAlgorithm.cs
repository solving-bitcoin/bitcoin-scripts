// Ignore Spelling: Damm

namespace CheckDigits.Net.GeneralAlgorithms;

/// <summary>
///   Algorithm developed by H. Michael Damm that uses a quasigroup table 
///   instead of modulus operations.
/// </summary>
/// <remarks>
///   <para>
///   Valid characters are decimal digits (0-9).
///   </para>
///   <para>
///   Check digit calculated by the algorithm is a decimal digit (0-9).
///   </para>
///   <para>
///   Assumes that the check digit (if present) is the right-most digit in the
///   input value.
///   </para>
///   <para>
///   Will detect all single-digit transcription errors and all two digit 
///   transpositions of adjacent digits.
///   </para>
///   <para>
///   This algorithm implements <see cref="IMaskedCheckDigitAlgorithm"/> 
///   and can validate values that contain non-check digit characters (such as 
///   spaces or dashes for human readability) when used with an 
///   <see cref="ICheckDigitMask"/>. Note that the trailing check digit 
///   character is never masked.
///   </para>
/// </remarks>
public sealed class DammAlgorithm : ISingleCheckDigitAlgorithm, IMaskedCheckDigitAlgorithm
{
   private static readonly DammQuasigroupTable _quasigroupTable =
      DammQuasigroupTable.Instance;
   private const Int32 _validateMinLength = 2;

   /// <inheritdoc/>
   public String AlgorithmDescription => Resources.DammAlgorithmDescription;

   /// <inheritdoc/>
   public String AlgorithmName => Resources.DammAlgorithmName;

   /// <inheritdoc/>
   public Boolean TryCalculateCheckDigit(String value, out Char checkDigit)
   {
      checkDigit = Chars.NUL;
      if (String.IsNullOrEmpty(value))
      {
         return false;
      }

      var interim = 0;
      var processLength = value.Length;
      for (var index = 0; index < processLength; index++)
      {
         var current = value[index].ToIntegerDigit();
         if (current.IsInvalidDigit())
         {
               return false;
         }
         interim = _quasigroupTable[interim, current];
      }

      checkDigit = interim.ToDigitChar();
      return true;
   }

   /// <inheritdoc/>
   public Boolean Validate(String value)
   {
      if (String.IsNullOrEmpty(value) || value.Length < _validateMinLength)
      {
         return false;
      }

      var interim = 0;
      var processLength = value.Length;
      for (var index = 0; index < processLength; index++)
      {
         var current = value[index].ToIntegerDigit();
         if (current.IsInvalidDigit())
         {
            return false;
         }
         interim = _quasigroupTable[interim, current];
      }

      return interim == 0;
   }

   /// <inheritdoc/>
   public Boolean Validate(String value, ICheckDigitMask mask)
   {
      if (mask is null)
      {
         throw new ArgumentNullException(nameof(mask), Resources.NullMaskMessage);
      }
      if (String.IsNullOrEmpty(value))
      {
         return false;
      }

      var interim = 0;
      var processedDigits = 0;
      var processLength = value.Length - 1;
      for (var index = 0; index < processLength; index++)
      {
         if (mask.ExcludeCharacter(index))
         {
            continue;
         }
         var current = value[index].ToIntegerDigit();
         if (current.IsInvalidDigit())
         {
            return false;
         }
         interim = _quasigroupTable[interim, current];
         processedDigits++;
      }
      if (processedDigits == 0)
      {
         return false;
      }

      var checkDigit = value[^1].ToIntegerDigit();
      if (checkDigit.IsInvalidDigit())
      {
         return false;
      }
      
      interim = _quasigroupTable[interim, checkDigit];
      return interim == 0;
   }
}
