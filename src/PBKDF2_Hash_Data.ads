with System,
     Interfaces,
     Interfaces.C,
     Windows_Data_Types,
     Wrapper_ZeroMemory;

package PBKDF2_Hash_Data with SPARK_Mode is

   use System,
       Interfaces,
       Interfaces.C,
       Windows_Data_Types;

   pragma Assertion_Policy (Check);

   subtype Pswd                is String (1 .. 512)
     with Dynamic_Predicate => (for all P of Pswd => P in '!' .. '~');

   subtype Pswd_Length         is Positive range 12 .. Pswd'Last;

   subtype New_Hash            is String (1 .. 64)
     with Dynamic_Predicate =>
       (for all I of New_Hash => I in 'A' .. 'Z' | '0' .. '9');

   subtype Salt_Enconde        is String (1 .. 344)
     with Dynamic_Predicate =>
       (for all S of Salt_Enconde => S
          in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '+' | '/' | '=');

   subtype Salt_Enconde_Length is Positive range 44 .. 344;
   subtype Salt_Max_Bytes      is Positive range 32 .. 256;

   --========================================================================--

   type Data is record
      Password        : Pswd                := (others => '0');
      Password_Length : Pswd_Length         := 12;
      Salt            : Salt_Enconde        := (others => '0');
      Salt_Length     : Salt_Enconde_Length := 44;
      Salt_Maximum    : Salt_Max_Bytes      := 32;
      Hash            : New_Hash            := (others => '0');
      Status          : NTSTATUS            := NTSTATUS'Last;
   end record;

   --  Procedure Public_Hash Generate Hash and Salt enconde
   --
   --  @param Item The data structure containing the password, salt, and status
   --
   --  @note Precondition:
   --  * Input password cannot be empty or all zeros.
   --  * Salt and Hash fields must be cleared (all zeros) before calling,
   --  * Status must be differente from success (0);
   --
   --  @note Postconditions:
   --  * The input Password is guaranteed to be
   --    securely wiped (overwritten with '0').
   --  * If Status is success (0):
   --    - The generated Salt will be populated up to Salt_Length.
   --    - Any remaining bytes in the Salt array will be padded with '0'.
   --  * If Status fails (not 0):
   --    - The Salt array is fully wiped to '0'.
   --
   --  @see Wrapper_ZeroMemory.Secure_Clean

   procedure Public_Hash (Item : in out Data)
     with Global  => (In_Out => Wrapper_ZeroMemory.Secure_Clean),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                 Wrapper_ZeroMemory.Secure_Clean =>
                   (Item, Wrapper_ZeroMemory.Secure_Clean)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then (for all S of Item.Salt => S = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then
       (if Item.Status = 0 and then Item.Salt_Length < Item.Salt'Length then
          Item.Salt (1 .. Item.Salt_Length) /= (1 .. Item.Salt_Length => '0')
        and then Item.Salt (Item.Salt_Length + 1 .. Item.Salt'Length)
        = (Item.Salt_Length + 1 .. Item.Salt'Length => '0')

          elsif Item.Status = 0
        and then Item.Salt_Length = Item.Salt'Length
          then

            Item.Salt /= (Item.Salt'Range => '0')

          else

            (for all C of Item.Salt => C = '0'));

   --========================================================================--

   --  Function Get_Iterations
   --  Retrieves the secure work factor (iteration count) configured for PBKDF2
   --
   --  @return The total number of cryptographic iterations to execute.
   function Get_Iterations return Interfaces.C.unsigned_long_long;

   type Verify_Data is record
      Password        : Pswd                := (others => '0');
      Password_Length : Pswd_Length         := 12;
      Salt            : Salt_Enconde        := (others => '0');
      Salt_Length     : Salt_Enconde_Length := 44;
      Hash            : New_Hash            := (others => '0');
      Iteration       : UULONG              := Get_Iterations;
      Diff            : Unsigned_8          := 16#FF#;
      Matches         : Boolean             := False;
      Status          : NTSTATUS            := NTSTATUS'Last;
   end record;

   --  Procedure Public_Verify
   --  Executes a secure, constant-time verification of a candidate password.
   --
   --  @param Item The verification data structure containing parameters.
   --
   --  @note Preconditions:
   --  * The input Password must not be empty or all zeros.
   --
   --  @note Postconditions:
   --  * The input Password is guaranteed to be
   --    securely wiped (overwritten with '0').
   --
   --  * The input Salt array is guaranteed to be
   --    securely wiped (overwritten with '0').
   --
   --  * The input Hash array is guaranteed to be
   --    securely wiped (overwritten with '0').
   --
   --  * Item.Matches will evaluate to True
   --    if and only if Item.Diff is equal to 0.
   --
   --  * If Item.Matches evaluates to True,
   --    the execution Status must be success (0).
   --
   --  @see Wrapper_ZeroMemory.Secure_Clean
   procedure Public_Verify (Item : in out Verify_Data)
     with Global  => (In_Out => Wrapper_ZeroMemory.Secure_Clean),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                 Wrapper_ZeroMemory.Secure_Clean =>
                   (Item, Wrapper_ZeroMemory.Secure_Clean)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then Item.Salt /= (Item.Salt'Range => '0')
     and then Item.Hash /= (Item.Hash'Range => '0')
     and then Item.Diff = 16#FF#
     and then Item.Matches = False
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then (for all S of Item.Salt => S = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Matches = (Item.Diff = 0)
     and then (if Item.Matches then Item.Status = 0);

private

   pragma Linker_Options ("-lbcrypt");

   subtype Hash_Natural_DM_R   is Natural  range 1 .. 16;
   subtype Hash_Natural_DM     is Natural  range 0 .. 255;

   subtype Hash_Buffer_Index_1 is Positive range 1 .. 63;
   subtype Hash_Buffer_Index_2 is Positive range 2 .. 64;

   subtype Hash_Buffer_Index   is Positive range 1 .. 32;
   type Hash_Raw_Array is array (Hash_Buffer_Index) of Unsigned_8;

   --  Procedure Hash
   --
   --  @note: identical preconditions, postconditions, and data-flow
   --        contracts from Public_Hash.
   --  @see Public_Hash
   procedure Hash (Item : in out Data)
     with Global  => (In_Out => Wrapper_ZeroMemory.Secure_Clean),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                 Wrapper_ZeroMemory.Secure_Clean =>
                   (Item, Wrapper_ZeroMemory.Secure_Clean)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then (for all S of Item.Salt => S = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then
       (if Item.Status = 0 and then Item.Salt_Length < Item.Salt'Length then
          Item.Salt (1 .. Item.Salt_Length) /= (1 .. Item.Salt_Length => '0')
        and then Item.Salt (Item.Salt_Length + 1 .. Item.Salt'Length)
        = (Item.Salt_Length + 1 .. Item.Salt'Length => '0')

          elsif Item.Status = 0
        and then Item.Salt_Length = Item.Salt'Length
          then

            Item.Salt /= (Item.Salt'Range => '0')

          else

            (for all C of Item.Salt => C = '0'));

   --========================================================================--

   --  Procedure Verify
   --
   --  @note: identical preconditions, postconditions, and data-flow
   --        contracts from Public_Verify.
   --  @see Public_Verify
   procedure Verify (Item : in out Verify_Data)
     with Global  => (In_Out => Wrapper_ZeroMemory.Secure_Clean),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                 Wrapper_ZeroMemory.Secure_Clean =>
                   (Item, Wrapper_ZeroMemory.Secure_Clean)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then Item.Salt /= (Item.Salt'Range => '0')
     and then Item.Hash /= (Item.Hash'Range => '0')
     and then Item.Diff = 16#FF#
     and then Item.Matches = False
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then (for all S of Item.Salt => S = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Matches = (Item.Diff = 0)
     and then (if Item.Matches then Item.Status = 0);

   --========================================================================--

   subtype WUULONG       is Interfaces.C.unsigned_long_long
   range 650_000 .. 1_000_000;

   subtype WULONG_CBPDAT is Interfaces.C.unsigned_long range 12 .. 512;
   subtype WULONG_CBSALT is Interfaces.C.unsigned_long range 32 .. 256;
   subtype WULONG_CBDDKY is Interfaces.C.unsigned_long range 1 .. 32;
   subtype DWFLAGS_0     is Interfaces.C.unsigned_long range 0 .. 0;
   subtype LPCWSTR_OPT   is System.Address;
   subtype LPCWSTR       is Interfaces.C.wchar_array;

   Alg_Name_W : constant LPCWSTR :=
     Interfaces.C.To_C (Item       => "SHA256",
                        Append_Nul => True)
     with Convention => C;

   BCRYPT_ALG_HANDLE_HMAC_FLAG : constant ULONG    := 8;
   STATUS_SUCCESS              : constant NTSTATUS := 0;
   Null_Address_Algorithm      : constant POINTER  := System.Null_Address;
   Iterations                  : constant WUULONG  := WUULONG'Last;

   --  @Implementation
   function Get_Iterations return Interfaces.C.unsigned_long_long is
     (Iterations);

   --  Initializes a CNG cryptographic algorithm provider handle.
   --
   --  @param phAlgorithm Pointer that receives the provider handle.
   --  @param pszAlgId    Unicode string for algorithm (Alg_Name_W).
   --  @param pszImpl     The specific implementation (Must be NULL).
   --  @param dwFlags     Flags for provider behavior (Must be 8/HMAC).
   --  @return NTSTATUS code (0 for STATUS_SUCCESS).
   --
   --  @note Preconditions:
   --  - phAlgorithm cannot be a null address.
   --  - pszImpl must remain a null address.
   --  - dwFlags must strictly equal 8 to force HMAC execution.
   function BCryptOpenAlgorithmProvider
     (phAlgorithm : POINTER;
      pszAlgId    : LPCWSTR     := Alg_Name_W;
      pszImpl     : LPCWSTR_OPT := System.Null_Address;
      dwFlags     : ULONG       := BCRYPT_ALG_HANDLE_HMAC_FLAG)
      return NTSTATUS
     with
       Import        => True,
       Convention    => Stdcall,
       External_Name => "BCryptOpenAlgorithmProvider",
       Pre  => phAlgorithm /= System.Null_Address
       and then pszImpl     = System.Null_Address
       and then dwFlags     = 8;

   --  Derives a cryptographic key from a password using PBKDF2.
   --
   --  @param hAlgorithm   The algorithm handle from Open provider.
   --  @param pbPassword   Pointer to the buffer containing password bytes.
   --  @param cbPassword   The size, in bytes, of the password buffer.
   --  @param pbSalt       Pointer to the buffer containing salt bytes.
   --  @param cbSalt       The size, in bytes, of the salt buffer.
   --  @param cIterations  The number of iterations to perform.
   --  @param pbDerivedKey Pointer to output buffer for the derived key.
   --  @param cbDerivedKey The size, in bytes, of the output buffer.
   --  @param dwFlags      Execution flags (Reserved, must be 0).
   --  @return NTSTATUS code (0 for STATUS_SUCCESS).
   --
   --  @note Preconditions:
   --  - All major pointers (hAlgorithm, pbPassword, pbSalt, pbDerivedKey)
   --    must be valid and distinct from System.Null_Address.
   function BCryptDeriveKeyPBKDF2
     (hAlgorithm   : POINTER;
      pbPassword   : POINTER;
      cbPassword   : WULONG_CBPDAT;
      pbSalt       : POINTER;
      cbSalt       : WULONG_CBSALT;
      cIterations  : WUULONG   := Iterations;
      pbDerivedKey : POINTER;
      cbDerivedKey : WULONG_CBDDKY;
      dwFlags      : DWFLAGS_0 := 0)
      return NTSTATUS
     with
       Import        => True,
       Convention    => Stdcall,
       External_Name => "BCryptDeriveKeyPBKDF2",
       Pre => hAlgorithm     /= System.Null_Address
       and then pbPassword   /= System.Null_Address
       and then pbSalt       /= System.Null_Address
       and then pbDerivedKey /= System.Null_Address;

   --  Closes a cryptographic algorithm provider handle and resources.
   --
   --  @param hAlgo   The valid algorithm provider handle to close.
   --  @param dwFlags Flags (Reserved, must be 0).
   --  @return NTSTATUS code (0 for STATUS_SUCCESS).
   --
   --  @note Preconditions:
   --  - The provider handle (hAlgo) cannot be a null address.
   function BCryptCloseAlgorithmProvider
     (hAlgo   : POINTER;
      dwFlags : DWFLAGS_0 := 0)
      return NTSTATUS
     with
       Import        => True,
       Convention    => Stdcall,
       External_Name => "BCryptCloseAlgorithmProvider",
       Pre => hAlgo    /= System.Null_Address;

end PBKDF2_Hash_Data;
