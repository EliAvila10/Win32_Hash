with System,
     Interfaces,
     Interfaces.C,
     Ada.Real_Time;

with Windows_Data_Types;

package Wrapper_BcryptGenRandom with SPARK_Mode is

   pragma Assertion_Policy (Check);

   use System,
       Interfaces,
       Interfaces.C,
       Ada.Real_Time;

   use Windows_Data_Types;

   --  Secure public wrapper to generate random bytes using BCryptGenRandom.
   --
   --  @param Buffer The output array to receive the random byte stream.
   --  @param Status Returns 0 (BCRYPT_SUCCESS) on success, or error code.
   --
   --  @note Preconditions:
   --  - Buffer array index must start at 0.
   --  - Buffer length must be at least 32 bytes for entropy safety.
   --  @note Postconditions:
   --  - If Status is 0, Buffer is proven to contain randomized data.
   --  - If Status fails, Buffer is guaranteed to be entirely zeroed out.
   procedure BcryptGenRandom_Public
     (Buffer : out BUFFER_RNG; 
      Status : out NTSTATUS)   
     with
       Global  => (Input  => Ada.Real_Time.Clock_Time),
       Depends => (Buffer => null,
                   Status => null,
                   null   => Ada.Real_Time.Clock_Time),
       Pre     => Buffer'First = 0
       and then Buffer'Length >= 32,
       Post    => (if Status = 0 then
                     Buffer /= (Buffer'Range => 0)
                       else
                         Buffer = (Buffer'Range => 0));

private

   pragma Linker_Options ("-lbcrypt");

   Interval          : constant Ada.Real_Time.Time_Span :=
     Milliseconds (MS => 2_000);

   Retry             : Ada.Real_Time.Time               :=
     Ada.Real_Time.Clock;

   BCRYPT_ALG_HANDLE               : constant POINTER  := System.Null_Address;
   BCRYPT_USE_SYSTEM_PREFERRED_RNG : constant ULONG    := 16#0000_0002#;
   BCRYPT_SUCCESS                  : constant NTSTATUS := 0;

   --  Direct Windows API import for the native BCryptGenRandom subsystem.
   --
   --  @param hAlgorithm Algorithm provider handle (Defaults to Null_Address).
   --  @param pbBuffer Pointer to the destination buffer receiving the data.
   --  @param cbBuffer The total number of bytes to request from the PRNG.
   --  @param dwFlags Execution flags (Defaults to system preferred RNG).
   --  @return NTSTATUS code (Returns 0 indicating success).
   --
   --  @note Preconditions:
   --  - The destination memory pointer pbBuffer cannot be a null address.
   --  - The requested size cbBuffer must be greater than or equal to 1.
   function BCryptGenRandom
     (hAlgorithm : POINTER := BCRYPT_ALG_HANDLE;
      pbBuffer   : POINTER;
      cbBuffer   : ULONG;
      dwFlags    : ULONG := BCRYPT_USE_SYSTEM_PREFERRED_RNG)
      return NTSTATUS
     with
       Import     => True,
       Convention => C,
       Link_Name  => "BCryptGenRandom",
       Global     => null,
       Pre        => pbBuffer /= System.Null_Address and then cbBuffer >= 1;

end Wrapper_BcryptGenRandom;
