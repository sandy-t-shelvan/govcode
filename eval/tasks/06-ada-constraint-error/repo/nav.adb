package body Nav is

   function Turn (From, To : Degrees) return Degrees is
   begin
      return To - From;
   end Turn;

end Nav;
