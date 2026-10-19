package body Wrapper_ZeroMemory with SPARK_Mode,
  Refined_State => (Secure_Clean => null)
is

   --------------------------------
   --  SecureZeroMemory Strings  --
   --------------------------------
   procedure SecureZeroMemory_Strings (Item : in out String)
     with SPARK_Mode => off
   is
   begin

      SecureZeroMemory
        (Address => Item     (Item'First)'Address,
         Size    => C_Size_T (Item'Length));

      Item := (others => '0');

   end SecureZeroMemory_Strings;

   ------------------------------
   --  SecureZeroMemory Bytes  --
   ------------------------------
   procedure SecureZeroMemory_Bytes (Item : in out BUFFER_RNG)
     with SPARK_Mode => off
   is
   begin

      SecureZeroMemory
        (Address => Item     (Item'First)'Address,
         Size    => C_Size_T (Item'Length));

      Item := (others => 0);

   end SecureZeroMemory_Bytes;

end Wrapper_ZeroMemory;
