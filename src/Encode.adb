package body Encode with SPARK_Mode is

   subtype Byte        is Natural range 0 .. 255;
   subtype Sextet      is Natural range 0 .. 63;
   subtype Padding     is Natural range 0 .. 2;
   subtype Start_Group is Natural range 0 .. 255;

   -------------------
   --  Salt Encode  --
   -------------------
   procedure Salt_Encode
     (Item          :     BUFFER_RNG;
      Length        :     Salt_Length := 32;
      To_Base64     : out Base64_Text;
      Base64_Length : out Base64_Len;
      Valid         : out Boolean)
   is

      Total      : constant Base64_Len        := 4 * ((Length + 2) / 3);
      Pad        : constant Padding           := (3 - Length mod 3) mod 3;
      First      : constant BUFFER_RNG_LENGTH := Item'First;
      G          : Start_Group;
      B0, B1, B2 : Byte;
      S          : Sextet;

   begin
      Base64_Length := Total;
      To_Base64     := (others => '0');

      for I in Base64_Range range 1 .. Total loop
         G  := 3 * ((I - 1) / 4);

         B0 := (if G     < Length then
                   Byte (Item (First + BUFFER_RNG_LENGTH (G)))     else 0);
         B1 := (if G + 1 < Length then
                   Byte (Item (First + BUFFER_RNG_LENGTH (G + 1))) else 0);
         B2 := (if G + 2 < Length then
                   Byte (Item (First + BUFFER_RNG_LENGTH (G + 2))) else 0);

         S := (case (I - 1) mod 4 is
                  when 0      => B0 / 4,
                  when 1      => B0 mod 4 * 16 + B1 / 16,
                  when 2      => B1 mod 16 * 4 + B2 / 64,
                  when others => B2 mod 64);

         To_Base64 (I) :=
           (if    I > Total - Pad then '='
            elsif S < 26 then Character'Val (Character'Pos ('A') + S)
            elsif S < 52 then Character'Val (Character'Pos ('a') + S - 26)
            elsif S < 62 then Character'Val (Character'Pos ('0') + S - 52)
            elsif S = 62 then '+'
            else '/');

         pragma Loop_Invariant
           (for all J in 1 .. I =>
              (if J > Total - Pad
               then To_Base64 (J) = '='
               else To_Base64 (J) in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'
                                   | '+' | '/'));
      end loop;

      Valid := (for all I in 1 .. Total =>
                  (if I > Total - Pad
                   then To_Base64 (I) = '='
                   else To_Base64 (I) in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'
                       | '+' | '/'));

      if not Valid then
         To_Base64 := (others => '0');
      end if;

   end Salt_Encode;

end Encode;
