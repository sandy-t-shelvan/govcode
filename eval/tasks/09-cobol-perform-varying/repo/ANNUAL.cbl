      *> ANNUAL - sum twelve monthly amounts
       IDENTIFICATION DIVISION.
       PROGRAM-ID. ANNUAL.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-MONTHS.
           05  WS-AMT        PIC 9(5)V99 OCCURS 12 TIMES.
       01  WS-I              PIC 99      VALUE ZERO.
       01  WS-TOTAL          PIC 9(7)V99 VALUE ZERO.
       01  WS-OUT            PIC Z(6)9.99.
       PROCEDURE DIVISION.
       MAIN-PARA.
           PERFORM LOAD-AMOUNTS.
           PERFORM SUM-AMOUNTS.
           MOVE WS-TOTAL TO WS-OUT.
           DISPLAY "ANNUAL=" WS-OUT.
           STOP RUN.
       LOAD-AMOUNTS.
           PERFORM VARYING WS-I FROM 1 BY 1 UNTIL WS-I > 12
               COMPUTE WS-AMT(WS-I) = WS-I * 100
           END-PERFORM.
       SUM-AMOUNTS.
           PERFORM VARYING WS-I FROM 1 BY 1 UNTIL WS-I > 11
               ADD WS-AMT(WS-I) TO WS-TOTAL
           END-PERFORM.
