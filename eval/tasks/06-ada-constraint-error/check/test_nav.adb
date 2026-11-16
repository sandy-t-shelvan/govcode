with Ada.Text_IO; use Ada.Text_IO;
with Nav;
procedure Test_Nav is
   procedure Expect (From, To, Want : Integer) is
      Got : constant Integer := Nav.Turn (From, To);
   begin
      if Got /= Want then
         Put_Line ("FAIL Turn" & From'Image & To'Image & " =" & Got'Image);
         raise Program_Error;
      end if;
   end Expect;
begin
   Expect (10, 50, 40);
   Expect (350, 10, 20);
   Expect (90, 90, 0);
   Expect (0, 359, 359);
   Expect (359, 0, 1);
   Put_Line ("ok");
end Test_Nav;
