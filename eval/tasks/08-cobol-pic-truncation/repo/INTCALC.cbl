      *> INTCALC - simple interest on deposit (fixed format)
       IDENTIFICATION DIVISION.
       PROGRAM-ID. INTCALC.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-PRINCIPAL      PIC 9(7)V99  VALUE 10000.00.
       01  WS-RATE           PIC V99      VALUE ZERO.
       01  WS-INTEREST       PIC 9(7)V99  VALUE ZERO.
       01  WS-OUT            PIC Z(6)9.99.
       PROCEDURE DIVISION.
       MAIN-PARA.
           MOVE 0.0525 TO WS-RATE.
           PERFORM CALC-INTEREST.
           MOVE WS-INTEREST TO WS-OUT.
           DISPLAY "INTEREST=" WS-OUT.
           STOP RUN.
       CALC-INTEREST.
           COMPUTE WS-INTEREST ROUNDED = WS-PRINCIPAL * WS-RATE.
