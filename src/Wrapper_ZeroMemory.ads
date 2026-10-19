with System;
with Interfaces;
with Interfaces.C;
with Windows_Data_Types;

package Wrapper_ZeroMemory with SPARK_Mode,
  Abstract_State => (Secure_Clean with Ghost)
is

   use System;
   use Interfaces;
   use Interfaces.C;
   use Windows_Data_Types;

   pragma Assertion_Policy (Check);

   --  Securely overwrites a String buffer with '0' characters.
   --
   --  @param Item The string buffer to be cleared in memory.
   --
   --  @note Preconditions:
   --  - The string length must be greater than or equal to 1.
   --  @note Postconditions:
   --  - All components within the string range are proven to be '0'.
   procedure SecureZeroMemory_Strings
     (Item : in out String)
     with Global => (Output => Secure_Clean),
     Depends     => (Item         => null,
                     Secure_Clean => Item),
     Pre         => Item'Length >= 1,
     Post        => (for all I in Item'Range => Item (I) = '0');

   --========================================================================--

   --  Securely overwrites a BUFFER_RNG byte array with 0 values.
   --
   --  @param Item The RNG buffer array to be cleared in memory.
   --
   --  @note Preconditions:
   --  - The buffer length must be greater than or equal to 1.
   --  @note Postconditions:
   --  - All components within the buffer range are proven to be 0.
   procedure SecureZeroMemory_Bytes
     (Item : in out BUFFER_RNG)
     with Global  => (Output => Secure_Clean),
     Depends      => (Item         => null,
                      Secure_Clean => Item),
     Pre          => Item'Length >= 1,
     Post         => (for all I in Item'Range => Item (I) = 0);

   --========================================================================--

   --  Direct Windows API import for the RtlSecureZeroMemory subsystem.
   --
   --  @param Address Starting memory address pointer to overwrite.
   --  @param Size The total number of bytes to fill with zeros.
   --
   --  @note Preconditions:
   --  - The Address pointer cannot be a null address.
   --  - Size must be greater than or equal to 1 byte.
   procedure SecureZeroMemory
     (Address : POINTER;
      Size    : C_Size_T)
     with Import => True,
     Convention  => Stdcall,
     Link_Name   => "RtlSecureZeroMemory",
     Pre         => Address /= System.Null_Address
     and then Size >= 1;

end Wrapper_ZeroMemory;
