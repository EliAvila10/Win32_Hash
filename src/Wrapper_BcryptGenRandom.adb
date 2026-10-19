with Wrapper_ZeroMemory;

package body Wrapper_BcryptGenRandom with SPARK_Mode => off is

   ------------------------------
   --  BcryptGenRandom Public  --
   ------------------------------
   procedure BcryptGenRandom_Public
     (Buffer : out BUFFER_RNG;
      Status : out NTSTATUS)
   is
      use Wrapper_ZeroMemory;
   begin

      Buffer := (others => 0);
      Status := NTSTATUS'Last;

      BGR :
      for I in reverse 1 .. 5 loop

         pragma Loop_Variant   (Decreases => I);

         Status := BCryptGenRandom
           (pbBuffer => Buffer (Buffer'First)'Address,
            cbBuffer => ULONG (Buffer'Length));  -->

         exit BGR when Status = BCRYPT_SUCCESS;

         SecureZeroMemory
           (Address => Buffer (Buffer'First)'Address,
            Size    => BUFFER_RNG_LENGTH (Buffer'Length));

         Buffer := (others => 0);

         Retry  := Ada.Real_Time.Clock + Interval;
         delay until Retry;

      end loop BGR;

   end BcryptGenRandom_Public;

end Wrapper_BcryptGenRandom;
