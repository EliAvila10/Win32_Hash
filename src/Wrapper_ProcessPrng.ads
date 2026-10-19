with System,
     Interfaces,
     Interfaces.C,
     Ada.Real_Time;

with Windows_Data_Types;

package Wrapper_ProcessPrng with SPARK_Mode is

   use System,
       Interfaces,
       Interfaces.C,
       Ada.Real_Time;

   use Windows_Data_Types;

   pragma Assertion_Policy (Check);

   --  Secure public wrapper to generate cryptographically random bytes.
   --
   --  @param Buffer The output array to receive the random byte stream.
   --  @param Status Returns 1 on success, or an error status on failure.
   --
   --  @note Preconditions:
   --  - Buffer array index must start at 0.
   --  - Buffer length must be at least 32 bytes for entropy safety.
   --  @note Postconditions:
   --  - If Status is 1, Buffer is proven to contain randomized data.
   --  - If Status fails, Buffer is guaranteed to be entirely zeroed out.
   procedure ProcessPrng_Public
     (Buffer : out BUFFER_RNG;
      Status : out NTSTATUS)
     with
       Global  => (Input => Ada.Real_Time.Clock_Time),
       Depends => (Buffer => null,
                   Status => null,
                   null   => Ada.Real_Time.Clock_Time),
       Pre     => Buffer'First = 0
       and then Buffer'Length >= 32,
       Post    => (if Status = 1 then
                     Buffer /= (Buffer'Range => 0)
                       else
                         Buffer = (Buffer'Range => 0));

private

   pragma Linker_Options ("C:/Windows/System32/BCryptPrimitives.dll");

   --  package Linker is
   --    for Default_Switches ("ada")
   --    use ("C:/Windows/System32/BCryptPrimitives.dll");
   --  end Linker;
   --  --> Add in .gpr if you want to remove pragma Linker_Options...

   Interval : constant Ada.Real_Time.Time_Span := Milliseconds (MS => 2_000);
   Retry    : Ada.Real_Time.Time           := Ada.Real_Time.Clock;

   ProcessPrng_Success : constant NTSTATUS := 1;

   --  Direct Windows API import for the native ProcessPrng subsystem.
   --
   --  @param pbData Base memory address pointer to the destination buffer.
   --  @param cbData The total number of bytes to request from the OS PRNG.
   --  @return NTSTATUS code (Returns 1 indicating success).
   --
   --  @note Preconditions:
   --  - The destination memory pointer pbData cannot be a null address.
   --  - The requested size cbData must be greater than or equal to 1.
   function ProcessPrng
     (pbData : POINTER;
      cbData : BUFFER_RNG_LENGTH)
      return NTSTATUS
     with
       Import     => True,
       Convention => C,
       Link_Name  => "ProcessPrng",
       Global     => null,
       Pre        => pbData /= System.Null_Address and then cbData >= 1;

   pragma Weak_External (ProcessPrng);

end Wrapper_ProcessPrng;
