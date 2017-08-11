/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** texp.h: Exponentiation mit simuliertem Timing
**/

#define nbits 128 /* die Rechenlaenge */ 

/* Aus longint.h */
#ifndef MAXNBITS
#  define MAXNBITS  4096
#endif
#define MAXNLONGS  (MAXNBITS/32)

/* LITModExp (z_in, x, y, n):
 * x_in = (x^y) mod n, return timing
 */
// unsigned long LITModExp(longnum_ptr z_in, const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
unsigned long LITModExp(mpz_t z_in, mpz_t x, mpz_t y, mpz_t n);

/* LITTimeModExp (x,y,n)
 * Berechnet Timing fuer (x^y) mod n
 */
// unsigned long LITTimeModExp (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
unsigned long LITTimeModExp (mpz_t x, mpz_t y, mpz_t n);

/* LITTimeModMult (x,y,n)
 * Berechnet Timing fuer (x*y) mod n
 * Das Timing ist *nicht* kommutativ!
 */
// unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
unsigned long LITTimeModMult (mpz_t x, mpz_t y, mpz_t n);

/* LITTimeModSquare (x, n)
 * Berechnet Timing fuer (x^2) mod n
 * (x^2) mod n ist halb so teuer wie (x*x) mod n!
 */
// unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n);
unsigned long LITTimeModSquare (mpz_t x, mpz_t n);
