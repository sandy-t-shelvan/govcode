with Ada.Text_IO; use Ada.Text_IO;
with Sensors; use Sensors;
procedure Test_Sensors is
   procedure Expect (In_V, Lo, Hi, Want : Integer) is
      V : Integer := In_V;
   begin
      Clamp (V, Lo, Hi);
      if V /= Want then
         Put_Line ("FAIL Clamp" & In_V'Image & " ->" & V'Image);
         raise Program_Error;
      end if;
   end Expect;
begin
   Expect (150, 0, 100, 100);
   Expect (-5, 0, 100, 0);
   Expect (42, 0, 100, 42);
   Expect (7, 7, 7, 7);
   if Average (3, 4) /= 3 then
      raise Program_Error;
   end if;
   Put_Line ("ok");
end Test_Sensors;
