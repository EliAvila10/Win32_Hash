with Interfaces.C,
     Windows_Data_Types;

package Encode with SPARK_Mode is

   pragma Assertion_Policy (Check);

   use Interfaces.C,
       Windows_Data_Types;

   subtype Salt_Length   is Positive range 32 .. 256; --  Item (0 .. 255) = 256
   subtype Base64_Range  is Positive range 1 .. 344;  --  4 * ceil (256 / 3)
   subtype Base64_Len    is Positive range 44 .. 344; --  4 * ceil (32 / 3)
   subtype Base64_Text   is String (Base64_Range)
     with Dynamic_Predicate =>
       (for all B of Base64_Text => B
          in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '+' | '/' | '=');

   --  Encodes a raw byte salt buffer into a secure Base64 text string.
   --
   --  @param Item          The input byte buffer containing raw salt data.
   --  @param Length        The number of salt bytes to process (Default 32).
   --  @param To_Base64     The output buffer receiving the Base64 string.
   --  @param Base64_Length The actual number of valid bytes written.
   --
   --  @note Preconditions:
   --  - The input Item array range bounds must be mathematically valid.
   --   Item buffer size must be greater than or equal to the requested Length.
   --  @note Postconditions:
   --  - Base64_Length is proven to be correctly padded to 4-byte boundaries.
   --  - Valid output characters are guaranteed to conform to standard Base64.
   procedure Salt_Encode (Item          :     BUFFER_RNG;
                          Length        :     Salt_Length := 32;
                          To_Base64     : out Base64_Text;
                          Base64_Length : out Base64_Len;
                          Valid         : out Boolean)
     with Global  => null,
     Depends      => (To_Base64     => (Item, Length),
                      Base64_Length => Length,
                      Valid         => (Item, Length)),
     Pre          => Item'First <= Item'Last
     and then Item'Last - Item'First >= BUFFER_RNG_LENGTH (Length - 1),
     Post         => Base64_Length = 4 * ((Length + 2) / 3)
     and then (if Valid then
                 (for all I in 1 .. Base64_Length =>
                      (if I > Base64_Length - (3 - Length mod 3) mod 3
                           then To_Base64 (I) = '='
                         else To_Base64 (I)
                           in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'| '+' | '/'))
                   else
                 (for all I in To_Base64'Range => To_Base64 (I) = '0'));

end Encode;
