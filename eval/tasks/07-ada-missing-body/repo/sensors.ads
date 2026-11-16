package Sensors is

   --  Limit Value to the closed range Lo .. Hi (Lo <= Hi).
   procedure Clamp (Value : in out Integer; Lo, Hi : Integer);

   --  Integer mean of A and B, truncated toward zero.
   function Average (A, B : Integer) return Integer;

end Sensors;
