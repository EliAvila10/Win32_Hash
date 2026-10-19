with Encode,
     Decode,
     Wrapper_ProcessPrng,
     Wrapper_BcryptGenRandom;

package body PBKDF2_Hash_Data with SPARK_Mode is

   function High (P : Hash_Buffer_Index) return Hash_Buffer_Index_1 is
     ((P - 1) * 2 + 1)
       with
         Global     => null,
         Post       => High'Result mod 2 = 1;

   function Low (P : Hash_Buffer_Index) return Hash_Buffer_Index_2 is
     ((P - 1) * 2 + 2)
       with
         Global     => null,
         Post       => Low'Result mod 2 = 0;

   function Div (L : Hash_Natural_DM) return Hash_Natural_DM_R is
     ((L / 16) + 1)
       with
         Global     => null,
         Post       => Div'Result = (L / 16) + 1;

   function Med (L : Hash_Natural_DM) return Hash_Natural_DM_R is
     ((L mod 16) + 1)
       with
         Global     => null,
         Post       => Med'Result = (L mod 16) + 1;

   ---------------
   --  Convert  --
   ---------------
   procedure Convert (Hash  : in out New_Hash;
                      Bytes :        Hash_Raw_Array)
     with Global  => null,
     Depends => (Hash =>+ Bytes),
     Pre => (for all I of Hash => I = '0')
     and then Bytes /= (Bytes'Range => 0),
     Post => Hash /= (Hash'Range => '0')
   is
      Hex_Chain  : constant String (1 .. 16) := "0123456789ABCDEF";
   begin

      for K in Hash_Buffer_Index loop

         pragma Loop_Variant (Increases => K);

         pragma Loop_Invariant
           (if K > Hash_Buffer_Index'First then
              (for all I in Hash'First .. Low (P => K - 1)
               => Hash (I) in '0' .. '9' | 'A' .. 'F'));

         pragma Loop_Invariant
           (for all I in High (P => K) .. Hash'Last => Hash (I) = '0');

         pragma Loop_Invariant
           (if K > Hash_Buffer_Index'First and then
              (for some J in Hash_Buffer_Index'First .. K - 1
               => Bytes (J) /= 0) then Hash /= (Hash'Range => '0'));

         Hash (High (P => K)) := Hex_Chain (Div (Natural (Bytes (K))));

         pragma Assert (Hash (High (P => K)) in '0' .. '9' | 'A' .. 'F');

         Hash (Low (P => K))  := Hex_Chain (Med (Natural (Bytes (K))));

         pragma Assert (if Bytes (K) /= 0 then
                           Div (Natural (Bytes (K))) /= 1
                        or else Med (Natural (Bytes (K))) /= 1);

         pragma Assert (if Bytes (K) /= 0 then
                           Hash (High (P => K)) /= '0'
                        or else Hash (Low (P => K)) /= '0');

         pragma Assert (if (for some J in Hash_Buffer_Index'First .. K
                          => Bytes (J) /= 0) then Hash /= (Hash'Range => '0'));

      end loop;

   end Convert;

   --========================================================================--

   ------------
   --  Hash  --
   ------------
   procedure Hash (Item : in out Data)
     with SPARK_Mode => off
   is

      Ang_Handle : POINTER        := System.Null_Address;
      Rw_Result  : Hash_Raw_Array := (others => 0);

      Close      : NTSTATUS       := 0;
      pragma Unreferenced (Close);
      --  We use 'Unreferenced' because a failure to close the provider
      --  does not affect the success of the key derivation process.

      Salt       : BUFFER_RNG (0 .. C_Size_T (Item.Salt_Maximum - 1))
        := (others => 0);

      Status     : NTSTATUS := 2;

      Fatal_Error : exception;
   begin

      begin

         Wrapper_ProcessPrng.ProcessPrng_Public (Buffer => Salt,
                                                 Status => Status);

         if Status /= 1 then

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes (Item => Salt);
            Status := NTSTATUS'Last;
            Salt   := (others => 0);

            Wrapper_BcryptGenRandom.BcryptGenRandom_Public (Buffer => Salt,
                                                            Status => Status);

            if Status /= 0 then

               Wrapper_ZeroMemory.SecureZeroMemory_Strings
                 (Item => Item.Password);

               Wrapper_ZeroMemory.SecureZeroMemory_Bytes (Item => Salt);

               Item.Password := (others => '0');
               Salt          := (others => 0);

               raise Fatal_Error;

            end if;
         end if;

         if Salt /= (Salt'Range => 0) and then Status in 0 .. 1 then

            Item.Status := BCryptOpenAlgorithmProvider
              (phAlgorithm => Ang_Handle'Address);

            if Item.Status /= 0 or else Ang_Handle = System.Null_Address then

               Wrapper_ZeroMemory.SecureZeroMemory_Strings
                 (Item => Item.Password);

               Wrapper_ZeroMemory.SecureZeroMemory_Bytes
                 (Item => Salt);

               Item.Password := (others => '0');
               Salt          := (others => 0);

               raise Fatal_Error;
            end if;

            Item.Status := BCryptDeriveKeyPBKDF2
              (hAlgorithm   => Ang_Handle,
               pbPassword   => Item.Password (Item.Password'First)'Address,
               cbPassword   => WULONG_CBPDAT (Item.Password_Length),
               pbSalt       => Salt          (Salt'First)'Address,
               cbSalt       => WULONG_CBSALT (Salt'Length),
               pbDerivedKey => Rw_Result     (Rw_Result'First)'Address,
               cbDerivedKey => ULONG         (Rw_Result'Length));

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Password);

            Item.Password := (others => '0');

            Close      := BCryptCloseAlgorithmProvider (hAlgo => Ang_Handle);
            Ang_Handle := System.Null_Address;

            if Item.Status /= 0 then

               Wrapper_ZeroMemory.SecureZeroMemory_Bytes
                 (Item => BUFFER_RNG (Rw_Result));

               Wrapper_ZeroMemory.SecureZeroMemory_Bytes
                 (Item => Salt);

               Rw_Result := (others => 0);
               Salt      := (others => 0);

               raise Fatal_Error;

            end if;

            Convert (Hash  => Item.Hash,
                     Bytes => Rw_Result);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => BUFFER_RNG (Rw_Result));

            Rw_Result := (others => 0);

            declare
               Valid : Boolean := False;
            begin

               Encode.Salt_Encode
                 (Item          => Salt,
                  Length        => Positive (Salt'Length),
                  To_Base64     => Item.Salt,
                  Base64_Length => Item.Salt_Length,
                  Valid         => Valid);

               if not Valid then
                  raise Fatal_Error;
               end if;

            end;

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => Salt);

            Salt := (others => 0);

         else

            raise Fatal_Error;

         end if;

      exception
         when others =>

            if Ang_Handle /= System.Null_Address then
               Close := BCryptCloseAlgorithmProvider (hAlgo => Ang_Handle);
            end if;

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Salt);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Password);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Hash);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => Salt);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => BUFFER_RNG (Rw_Result));

            Item.Salt     := (others => '0');
            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);
            Rw_Result     := (others => 0);

      end;
   end Hash;

   -------------------
   --  Public Hash  --
   -------------------
   procedure Public_Hash (Item : in out Data) is
   begin
      Hash (Item => Item);
   end Public_Hash;

   --========================================================================--

   ----------------
   --  Verify    --
   ----------------
   procedure Verify (Item : in out Verify_Data)
     with SPARK_Mode => off
   is

      Ang_Handle : POINTER        := System.Null_Address;
      Rw_Result  : Hash_Raw_Array := (others => 0);

      Close      : NTSTATUS       := 0;
      pragma Unreferenced (Close);

      Salt       : BUFFER_RNG (0 .. 255) := (others => 0);
      Salt_Len   : Decode.Salt_Length;
      Valid      : Boolean        := False;

      Candidate  : New_Hash       := (others => '0');

      Fatal_Error : exception;
   begin

      begin

         Item.Status := BCryptOpenAlgorithmProvider
           (phAlgorithm => Ang_Handle'Address);

         if Item.Status /= 0 or else Ang_Handle = System.Null_Address then
            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Password);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Salt);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Hash);

            Item.Password := (others => '0');
            Item.Salt     := (others => '0');
            Item.Hash     := (others => '0');

            raise Fatal_Error;
         end if;

         Decode.Salt_Decode
           (From_Base64   => Item.Salt,
            Base64_Length => Item.Salt_Length,
            Item          => Salt,
            Length        => Salt_Len,
            Valid         => Valid);

         Wrapper_ZeroMemory.SecureZeroMemory_Strings
           (Item => Item.Salt);

         Item.Salt := (others => '0');

         if not Valid then

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Password);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Hash);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => Salt);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);

            raise Fatal_Error;
         end if;

         Item.Status := BCryptDeriveKeyPBKDF2
           (hAlgorithm   => Ang_Handle,
            pbPassword   => Item.Password (Item.Password'First)'Address,
            cbPassword   => WULONG_CBPDAT (Item.Password_Length),
            pbSalt       => Salt          (Salt'First)'Address,
            cbSalt       => WULONG_CBSALT (Salt_Len),
            cIterations  => Item.Iteration,
            pbDerivedKey => Rw_Result     (Rw_Result'First)'Address,
            cbDerivedKey => ULONG         (Rw_Result'Length));

         Wrapper_ZeroMemory.SecureZeroMemory_Strings
           (Item => Item.Password);

         Wrapper_ZeroMemory.SecureZeroMemory_Bytes
           (Item => Salt);

         Item.Password := (others => '0');
         Salt          := (others => 0);

         Close      := BCryptCloseAlgorithmProvider (hAlgo => Ang_Handle);
         Ang_Handle := System.Null_Address;

         if Item.Status /= 0 then

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => BUFFER_RNG (Rw_Result));

            Rw_Result := (others => 0);

            raise Fatal_Error;
         end if;

         Convert (Hash => Candidate, Bytes => Rw_Result);

         Wrapper_ZeroMemory.SecureZeroMemory_Bytes
           (Item => BUFFER_RNG (Rw_Result));

         Rw_Result := (others => 0);

         --  Constant Time Comparison
         Item.Diff := 0;
         for I in Candidate'Range loop
            Item.Diff := Item.Diff
              or (Unsigned_8 (Character'Pos (Candidate (I)))
                  xor Unsigned_8 (Character'Pos (Item.Hash (I))));
         end loop;

         Item.Matches := (Item.Diff = 0);

         Wrapper_ZeroMemory.SecureZeroMemory_Strings
           (Item => Candidate);

         Wrapper_ZeroMemory.SecureZeroMemory_Strings
           (Item => Item.Hash);

         Candidate := (others => '0');
         Item.Hash := (others => '0');

      exception
         when others =>

            if Ang_Handle /= System.Null_Address then
               Close := BCryptCloseAlgorithmProvider (hAlgo => Ang_Handle);
            end if;

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Password);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Salt);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Item.Hash);

            Wrapper_ZeroMemory.SecureZeroMemory_Strings
              (Item => Candidate);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => Salt);

            Wrapper_ZeroMemory.SecureZeroMemory_Bytes
              (Item => BUFFER_RNG (Rw_Result));

            Item.Password := (others => '0');
            Item.Salt     := (others => '0');
            Item.Hash     := (others => '0');
            Candidate     := (others => '0');
            Salt          := (others => 0);
            Rw_Result     := (others => 0);
      end;
   end Verify;

   ---------------------
   --  Public Verify  --
   ---------------------
   procedure Public_Verify (Item : in out Verify_Data) is
   begin
      Verify (Item => Item);
   end Public_Verify;

end PBKDF2_Hash_Data;
