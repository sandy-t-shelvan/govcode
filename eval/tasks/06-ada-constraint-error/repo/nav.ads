package Nav is
   subtype Degrees is Integer range 0 .. 359;

   --  Clockwise turn needed to go from heading From to heading To,
   --  in the range 0 .. 359.
   function Turn (From, To : Degrees) return Degrees;
end Nav;
