package body Decode with SPARK_Mode is

   subtype Sextet     is Natural range 0 .. 63;
   subtype Padding    is Natural range 0 .. 2;
   subtype Raw_Length is Natural range 0 .. 258;
   subtype Tail_Div   is Positive range 1 .. 16;
   subtype Byte_Pos   is Natural range 0 .. 258;

   -------------------
   --  Salt Decode  --
   -------------------
   procedure Salt_Decode
     (From_Base64   :     Base64_Text;
      Base64_Length :     Base64_Len;
      Item          : out BUFFER_RNG;
      Length        : out Salt_Length;
      Valid         : out Boolean)
   is
      Pad   : constant Padding :=
        (if    From_Base64 (Base64_Length)     /= '=' then 0
         elsif From_Base64 (Base64_Length - 1) /= '=' then 1
         else 2);

      Raw   : constant Raw_Length := 3 * (Base64_Length / 4) - Pad;

      Ok    : constant Boolean    := Base64_Length mod 4 = 0
        and then Raw in Salt_Length;

      Tail  : constant Tail_Div   :=
        (case Pad is when 0 => 1, when 1 => 4, when 2 => 16);

      First : constant BUFFER_RNG_LENGTH := Item'First;
      C     : Character;
      V     : Sextet_Value;
      S     : Sextet;
      Prev  : Sextet := 0;
      K     : Byte_Pos;
      B     : Byte;

   begin

      Item   := (others => 0);
      Length := (if Ok then Raw else Salt_Length'First);
      Valid  := Ok;

      for I in Base64_Range range 1 .. Base64_Length loop
         C := From_Base64 (I);
         V := Value (C);
         S := Sextet (Integer'Max (V, 0));

         Valid := Valid
           and then (if I > Base64_Length - Pad then C = '=' else V >= 0)
           and then (I /= Base64_Length - Pad or else S mod Tail = 0);

         K := 3 * ((I - 1) / 4) + (I - 1) mod 4;

         B := (case (I - 1) mod 4 is
                  when 1      => Prev * 4 + S / 16,
                  when 2      => Prev mod 16 * 16 + S / 4,
                  when others => Prev mod 4 * 64 + S);

         if (I - 1) mod 4 /= 0 and then K - 1 < Length then
            pragma Assert (B = Decoded_Byte (From_Base64, K - 1));
            Item (First + BUFFER_RNG_LENGTH (K - 1)) := UCHAR (B);
            pragma Assert
              (Natural (Item (First + BUFFER_RNG_LENGTH (K - 1)))
               = Decoded_Byte (From_Base64, K - 1));
         end if;
         Prev := S;

         pragma Loop_Invariant
           (Prev = Integer'Max (Value (From_Base64 (I)), 0));

         pragma Loop_Invariant
           (if Valid then
               Ok
            and then (for all J in 1 .. I =>
                        (if J > Base64_Length - Pad
                         then From_Base64 (J) = '='
                         else From_Base64 (J) in 'A' .. 'Z' | 'a' .. 'z'
                                               | '0' .. '9' | '+' | '/')));
         pragma Loop_Invariant
           (if Valid then
              (for all J in 0 .. Integer'Min
                   (3 * ((I - 1) / 4) + (I - 1)
                    mod 4, Length) - 1 =>
                 Natural (Item (First + BUFFER_RNG_LENGTH (J)))
                 = Decoded_Byte (From_Base64, J)));
      end loop;

      if not Valid then
         Wrapper_ZeroMemory.SecureZeroMemory_Bytes (Item => Item);
         Item := (others => 0);
      end if;

   end Salt_Decode;

end Decode;
