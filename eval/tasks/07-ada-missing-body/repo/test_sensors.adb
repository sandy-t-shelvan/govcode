with Ada.Text_IO; use Ada.Text_IO;
with Sensors; use Sensors;
procedure Test_Sensors is
   V : Integer := 150;
begin
   Clamp (V, 0, 100);
   if V /= 100 then
      Put_Line ("FAIL clamp high");
      raise Program_Error;
   end if;
   Put_Line ("ok");
end Test_Sensors;
