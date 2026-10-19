with Interfaces.C,
     Wrapper_ZeroMemory,
     Windows_Data_Types;

package Decode with SPARK_Mode is

   pragma Assertion_Policy (Check);

   use Interfaces.C,
       Windows_Data_Types;

   subtype Salt_Length   is Positive range 32 .. 256;
   subtype Salt_Index    is Natural  range 0 .. 255;

   subtype Base64_Range  is Positive range 1 .. 344;
   subtype Base64_Len    is Positive range 44 .. 344;
   subtype Base64_Text   is String (Base64_Range)
     with Dynamic_Predicate =>
       (for all B of Base64_Text => B
          in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '+' | '/' | '=');

   subtype Byte          is Natural  range 0 .. 255;
   subtype Sextet_Value  is Integer  range -1 .. 63;

   --  Converts a Base64 character to its corresponding 6-bit sextet value.
   --
   --  @param C The Base64 character to evaluate.
   --  @return The 6-bit integer value (0 to 63), or -1 if invalid.
   function Value (C : Character) return Sextet_Value is
     (if    C in 'A' .. 'Z' then Character'Pos (C) - Character'Pos ('A')
      elsif C in 'a' .. 'z' then Character'Pos (C) - Character'Pos ('a') + 26
      elsif C in '0' .. '9' then Character'Pos (C) - Character'Pos ('0') + 52
      elsif C = '+' then 62
      elsif C = '/' then 63
      else -1);

   --  Ghost function to calculate the mathematical value of a decoded byte.
   --
   --  @param Text The source Base64 string context.
   --  @param K    The objective index of the decoded salt byte array.
   --  @return The reconstructed raw byte integer value (0 to 255).
   function Decoded_Byte (Text : Base64_Text; K : Salt_Index) return Byte is
     (case K mod 3 is
        when 0 =>
          Integer'Max (Value (Text (4 * (K / 3) + 1)), 0) * 4
          + Integer'Max (Value (Text (4 * (K / 3) + 2)), 0) / 16,
        when 1 =>
          Integer'Max (Value (Text (4 * (K / 3) + 2)), 0) mod 16 * 16
          + Integer'Max (Value (Text (4 * (K / 3) + 3)), 0) / 4,
        when others =>
          Integer'Max (Value (Text (4 * (K / 3) + 3)), 0) mod 4 * 64
          + Integer'Max (Value (Text (4 * (K / 3) + 4)), 0))
   with Ghost;

   --  Decodes a Base64 text string back into a raw byte salt buffer.
   --
   --  @param From_Base64   The input Base64 encoded string buffer.
   --  @param Base64_Length The actual number of encoded bytes to process.
   --  @param Item          The destination byte array to store raw salt data.
   --  @param Length        The verified size of the extracted salt bytes.
   --  @param Valid         Returns True if the string was successfully decoded
   --
   --  @note Preconditions:
   --  - The output Item buffer must be large enough to hold max salt bounds.
   --  @note Postconditions:
   --  - If Valid, guarantees text bounds align properly to 4-byte packages.
   --  - Ensures every output byte matches the mathematical Decoded_Byte model.
   procedure Salt_Decode
     (From_Base64   :     Base64_Text;
      Base64_Length :     Base64_Len;
      Item          : out BUFFER_RNG;
      Length        : out Salt_Length;
      Valid         : out Boolean)
     with Global  => (In_Out => Wrapper_ZeroMemory.Secure_Clean),
     Depends      => (Item         => (Item, From_Base64, Base64_Length),
                      Length       => (From_Base64, Base64_Length),
                      Valid        => (From_Base64, Base64_Length),
                      Wrapper_ZeroMemory.Secure_Clean
                      => (Wrapper_ZeroMemory.Secure_Clean,
                          Item, From_Base64, Base64_Length)),
     Pre          => Item'First <= Item'Last
     and then Item'Last - Item'First
       >= BUFFER_RNG_LENGTH (Salt_Length'Last - 1),
     Post         => (if Valid then
                        Base64_Length mod 4 = 0
                      and then 3 * (Base64_Length / 4) - Length in 0 .. 2
                      and then (for all K in 0 .. Length - 1 =>
                                    Natural (Item (Item'First
                                  + BUFFER_RNG_LENGTH (K)))
                                = Decoded_Byte (From_Base64, K))
                        else
                          (for all K in Item'Range => Natural (Item (K)) = 0));

end Decode;
