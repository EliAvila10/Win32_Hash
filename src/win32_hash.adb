with Utilities,
     Interfaces,
     Interfaces.C,
     PBKDF2_Hash_Data,
     Wrapper_ZeroMemory;

procedure Win32_Hash is

   use Utilities,
       Interfaces,
       Interfaces.C,
       PBKDF2_Hash_Data;

   Password_1 : String := "Adaforum2026123!";
   Password_2 : String := "Adaforum20261231";

   Password_3 : String := "Adaforum2026123!";
   Password_4 : String := "Adaforum2026123!";

   Ok : Boolean;

   ---------------
   --  Example  --
   ---------------
   --  Hashes Hash_Pwd, then verifies Verify_Pwd against that hash.
   --  Both passwords are wiped right after being copied into the records.
   --  Ok = False only if hashing failed (nothing was verified).

   --    Example 1: verify with a DIFFERENT password  -> must fail.
   --    Example 2: verify with the SAME password     -> must succeed.
   --
   --  Password       Min -> 12, Max -> 512
   --  Bytes for salt Min -> 32, Max -> 256
   --  Main source of entropy: ProcessPrng, fallback BCryptGenRandom.

   procedure Example (Border     :        String;
                      Message    :        String;
                      Hash_Pwd   : in out String;
                      Verify_Pwd : in out String;
                      Ok         :    out Boolean)
   is

      --  Local records: each example starts from the default values, which
      --  already satisfy the Pre of Public_Hash (salt and hash all '0',
      --  Status /= 0) and are the fail cloced state for Public_Verify
      --  (Diff = 16#FF#, Matches = False, Status /= 0).
      To_Hash   : PBKDF2_Hash_Data.Data;
      To_Verify : PBKDF2_Hash_Data.Verify_Data;

   begin

      Ok := False;

      T_IO.Put_Line (Item => Border);
      T_IO.Put_Line (Item => Message);
      T_IO.Put_Line (Item => Border);

      T_IO.New_Line;

      T_IO.Put_Line (Item => Hashing);

      T_IO.New_Line;

      To_Hash.Password (1 .. Hash_Pwd'Length) := Hash_Pwd;
      To_Hash.Password_Length                 := Hash_Pwd'Length;

      To_Hash.Salt_Maximum := 32;
      --  Here you can add how many bytes you want for the salt.
      --  Min -> 32, Max -> 256
      --  By default are 32 bytes.

      --  We clear the password immediately after making a copy;
      --  the password in the record will be cleared within
      --  the 'Hash' and will return as all zeros.

      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => Hash_Pwd);
      --  Hash_Pwd := (others => '0');
      --  I'm commenting on this line so
      --  you can see the functionality of SecureZeroMemory.

      T_IO.Put_Line (Item => Password_Copying & Hash_Pwd);
      T_IO.New_Line;

      PBKDF2_Hash_Data.Public_Hash (Item => To_Hash);

      if To_Hash.Status = 0 then

         T_IO.Put_Line
           (Item => Success & Interfaces.C.long'Image (To_Hash.Status));

         T_IO.New_Line;

         T_IO.Put_Line
           (Item => Password_M
            & To_Hash.Password (1 .. To_Hash.Password_Length));

         T_IO.Put_Line
           (Item => Hash_M & To_Hash.Hash);

         T_IO.Put_Line
           (Item => Salt_M & To_Hash.Salt (1 .. To_Hash.Salt_Length)
            & Iterations & Interfaces.C.unsigned_long_long'Image
              (PBKDF2_Hash_Data.Get_Iterations));

      else

         T_IO.Put_Line
           (Item => Failed & Interfaces.C.long'Image (To_Hash.Status));

         T_IO.Put_Line
           (Item => Password_M
            & To_Hash.Password (1 .. To_Hash.Password_Length));

         T_IO.Put_Line
           (Item => Hash_M & To_Hash.Hash);

         T_IO.Put_Line
           (Item => Salt_M & To_Hash.Salt (1 .. To_Hash.Salt_Length));

         return;

      end if;

      T_IO.New_Line;

      --  If this were a registration, after saving to the database you
      --  would clean the salt and hash.

      --=====================================================================--

      T_IO.Put_Line (Item => Verifying);
      T_IO.New_Line;

      To_Verify.Password (1 .. Verify_Pwd'Length) := Verify_Pwd;
      To_Verify.Password_Length                   := Verify_Pwd'Length;

      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => Verify_Pwd);
      --  Verify_Pwd := (others => '0');

      T_IO.Put_Line (Item => Password_Copying & Verify_Pwd);
      T_IO.New_Line;

      --  What the database would have stored after registration:
      --  the salt, the hash, and the iterations used to generate it.
      To_Verify.Salt        := To_Hash.Salt;
      To_Verify.Salt_Length := To_Hash.Salt_Length;

      To_Verify.Hash        := To_Hash.Hash;

      --  Must be the SAME iterations used to generate the hash,
      --  otherwise the verification can never match.
      To_Verify.Iteration   := Get_Iterations;

      PBKDF2_Hash_Data.Public_Verify (Item => To_Verify);

      --  Whether the verification fails or not,
      --  the password, hash, and salt will all return as zero.

      if To_Verify.Status = 0 then
         T_IO.Put_Line
           (Item => Success & Interfaces.C.long'Image (To_Verify.Status));
      else
         T_IO.Put_Line
           (Item => Failed & Interfaces.C.long'Image (To_Verify.Status));
      end if;

      T_IO.New_Line;

      --  Three conditions on purpose: Status says the derivation worked,
      --  Diff (constant-time comparison) and Matches say the hash matched.
      if To_Verify.Status = 0
        and then To_Verify.Diff = 0
        and then To_Verify.Matches
      then

         T_IO.Put_Line (Item => Successful);

      else

         T_IO.Put_Line (Item => Unsuccessful);

      end if;

      T_IO.Put_Line
        (Item => Password_M
         & To_Verify.Password (1 .. To_Verify.Password_Length));

      T_IO.Put_Line
        (Item => Hash_M & To_Verify.Hash);

      T_IO.Put_Line
        (Item => Salt_M
         & To_Verify.Salt (1 .. To_Verify.Salt_Length));

      --  Public_Hash wipes only the password, not the salt or the hash,
      --  so the example wipes them by hand before the record goes away.
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Hash.Password);
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Hash.Salt);
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Hash.Hash);

      Ok := True;

   end Example;

begin

   Example (Border     => C1,
            Message    => Example_Message_1,
            Hash_Pwd   => Password_1,
            Verify_Pwd => Password_2,
            Ok         => Ok);

   if not Ok then
      return;
   end if;

   T_IO.New_Line;
   T_IO.New_Line;

   Example (Border     => C2,
            Message    => Example_Message_2,
            Hash_Pwd   => Password_3,
            Verify_Pwd => Password_4,
            Ok         => Ok);

end Win32_Hash;
