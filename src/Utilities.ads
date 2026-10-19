with Ada.Text_IO;

package Utilities is
   package T_IO renames Ada.Text_IO;

   Example_Message_1 : constant String :=
     "| Example with different passwords |";

   Example_Message_2 : constant String :=
     "| Example with same passwords |";

   Password_Copying  : constant String :=
     "Password after copying => ";

   Success           : constant String :=
     "Success [ Status ] =";

   Failed            : constant String :=
     "Failed [ Status ] =";

   Hashing           : constant String :=
     "Hashing...";

   Verifying         : constant String :=
     "Verifying...";

   Successful        : constant String :=
     "Successful verification!";

   Unsuccessful      : constant String :=
     "Unsuccessful verification!";

   Password_M        : constant String :=
     "Password => ";

   Hash_M            : constant String :=
     "Hash     => ";

   Salt_M            : constant String :=
     "Salt     => ";

   Iterations        : constant String :=
     " | Iteration =";

   C1 : constant String (1 .. Example_Message_1'Length) := (others => '=');
   C2 : constant String (1 .. Example_Message_2'Length) := (others => '=');

end Utilities;
