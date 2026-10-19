with Wrapper_ZeroMemory;

package body Wrapper_ProcessPrng with SPARK_Mode => Off is

   --------------------------
   --  ProcessPrng Public  --
   --------------------------
   procedure ProcessPrng_Public
     (Buffer : out BUFFER_RNG;
      Status : out NTSTATUS)
   is
      use Wrapper_ZeroMemory;
   begin

      Buffer := (others => 0);
      Status := NTSTATUS'Last;

      if ProcessPrng'Address /= System.Null_Address then

         PPG :
         for I in reverse 1 .. 5 loop

            pragma Loop_Variant   (Decreases => I);

            Status := ProcessPrng
              (pbData => Buffer (Buffer'First)'Address,
               cbData => BUFFER_RNG_LENGTH (Buffer'Length));

            exit PPG when Status = ProcessPrng_Success;

            SecureZeroMemory
              (Address => Buffer (Buffer'First)'Address,
               Size    => BUFFER_RNG_LENGTH (Buffer'Length));

            Buffer := (others => 0);

            Retry  := Ada.Real_Time.Clock + Interval;
            delay until Retry;

         end loop PPG;

      else
         Status := NTSTATUS'Last;
         return;
      end if;

   end ProcessPrng_Public;

end Wrapper_ProcessPrng;
