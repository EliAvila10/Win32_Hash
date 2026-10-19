with System,
     Interfaces.C,
     Interfaces;

package Windows_Data_Types with SPARK_Mode is

   subtype POINTER  is System.Address;

   subtype UCHAR    is Interfaces.Unsigned_8;
   subtype ULONG    is Interfaces.C.unsigned_long;
   subtype UULONG   is Interfaces.C.unsigned_long_long;
   subtype NTSTATUS is Interfaces.C.long;
   subtype BOOL     is Interfaces.C.int;
   subtype C_Size_T is Interfaces.C.size_t;

   subtype BUFFER_RNG_LENGTH is Interfaces.C.size_t;
   type BUFFER_RNG is array (BUFFER_RNG_LENGTH range <>) of UCHAR
     with Convention => C;

end Windows_Data_Types;
