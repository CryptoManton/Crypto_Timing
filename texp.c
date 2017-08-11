/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** texp.c: Exponentiation mit simuliertem Timing
**/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
++      								      ++
++  Copyright (C) 1995 Institut für Algorithmen und Kognitive Systeme         ++
++                     Universität Karlsruhe, Germany.			      ++
++  									      ++
++  All rights reserved.						      ++
++  									      ++
++  THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF Institut                   ++
++  für Algorithmen und Kognitive Systeme. The copyright		      ++
++  notice above does not imply evidence of any actual		              ++
++  or intended publication of such source code.			      ++
++  									      ++
++  Redistribution only with written permission of 			      ++
++  Institut für Algorithmen und Kognitive Systeme			      ++
++  									      ++
++  This software is distributed WITHOUT ANY WARRANTY;			      ++
++  without even the implied warranty of MERCHANTABILITY		      ++
++  or FITNESS FOR A PARTICULAR PURPOSE.				      ++
++     									      ++
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/***************************************************************************
 *                                                                         *
 *              Toolbox-Project --- Long Integer Arithmetics               *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 *   TEXP.C: Moduloexponentation (mit kuenstlichem Timing)                 *
 *                                                                         *
 ***************************************************************************
 *
 *    $RCSfile: texp.c,v $
 *   $Revision: 6.7 $
 *       $Date: 1996/01/28 19:23:43 $
 *     Creator: Steffen Stempel
 * Source-Host: Hades
 *     $Author: steffen $
 *     Support: PW, SD
 *    Machines: all
 *     $Locker:  $
 *      $State: Exp $
 *
 ***************************************************************************
 * $Log: exp.c,v $
 * Patched to do simple exponentiation with artificial timing value returned
 * by felix 96/05/22
 *
 * Revision 6.7  1996/01/28 19:23:43  steffen
 * version sync
 *
 * Revision 6.6  1995/12/03 18:23:49  steffen
 * - SAVE_STACK support: Temporary variables are MALLOC'ed using
 *   SVST_ALLOC_xxxx (which causes auto declarations if SAVE_STACK
 *   is not defined). An additional handle is passed to the modulo
 *   reduction function where it can store a pointer to dynamic
 *   allocated private data in. The contents of the handle are
 *   freed before finishing.
 *   This results in saving about 12KB of stack ...
 *
 * Revision 6.5  1995/08/30 15:28:31  steffen
 * - Changed RCS log entry to support RCS 5.7
 * - RCS_IDSTRING is now static
 *
 * Revision 6.4  1995/05/02  14:36:05  steffen
 * version sync
 *
 * Revision 6.3  1995/03/27  20:45:14  steffen
 * - changed LIIsFastModulus to isfastmodulus
 *
 * Revision 6.2  1995/03/24  12:30:19  steffen
 * version sync
 *
 * Revision 6.1  1995/03/21  20:12:31  steffen
 * - Parameter check for exponent
 *
 * Revision 6.0  1995/02/10  15:16:56  steffen
 * Initial creation from version 5.22
 *
 */

#include <gmp.h>
#include "texp.h"
#include "praktikum.h"

/*RCS_IDSTRING(static const char __RCSID__[] = "$Header: /home/steffen/toolbox/longint/RCS/exp.c,v 6.7 1996/01/28 19:23:43 steffen Exp $";)*/

/*
 * LIModExp(z,x,y,n) : Calculates z := x^y mod n
 *
 * RETURN: ----
 * RESULT: z
 */

#if 0
static int LIGetBit(mpz_t x/*const_longnum_ptr x*/, int pos)
{
  if (pos >= mpz_size(x)/*NBITS(x)*/) return 0;
  return (LONGNUM_GET_WORD(x,(pos>>4))&(1<<(pos&0xf)))!=0;

  // TODO was macht LONGNUM_GET_WORD?
}
#endif

static void hash_value (MD5_CTX *ct, /* const_longnum_ptr x*/ mpz_t x)
{
  int i;
  unsigned long h=0;
  int nlongs = (int)mpz_sizeinbase(x, 2)/32.f;
  if (mpz_sizeinbase(x, 2) % 32 != 0)
	  nlongs++;

  for (i = MAXNLONGS-1; i>= nlongs; i--) {
    MD5Update (ct, (unsigned char *) &h, 4);
  }
#ifdef LOWBYTEFIRST
  /* invert things hand to hash MSB first */
  unsigned long int b = mpz_get_ui(x);

  unsigned char *bi = malloc(sizeof(unsigned char));
  for (i = nlongs*4-1; i>= 0; i--) {
    *bi = b + i;
    MD5Update (ct, bi, 1);
  }
  free(bi);
#else
  unsigned long int l = mpz_get_ui(x);

  unsigned char *li = malloc(sizeof(unsigned char));
  for (i = nlongs-1; i >= 0; i--) {
    *li = l + nlongs-1-i;
    MD5Update (ct, li,4);
  }
  free(li);
#endif
}

//static unsigned long calc_timing (const_longnum_ptr a, const_longnum_ptr b)
static unsigned long calc_timing (mpz_t a, mpz_t b)
{
  static MD5_CTX ctx;
  static union {
    char d1[16];
    UINT4 d2[4];
  } digest;
  MD5Init (&ctx);
  hash_value (&ctx, a);
  hash_value (&ctx, b);
  MD5Final ((unsigned char *)digest.d1, &ctx);
  return ((digest.d2[0]>>2)+(digest.d2[1]>>2)+
          (digest.d2[2]>>2)+(digest.d2[3]>>2))>>13;
    /* room for 8192 operations, that's enough for up to 4096 bit numbers */
}

//unsigned long LITModExp(longnum_ptr z_in, const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n)
unsigned long LITModExp(mpz_t z_in, mpz_t x, mpz_t y, mpz_t n)
{
	unsigned long timing;
	int i, expbits;
	mpz_t yh, zh;
	mpz_init(yh);
	mpz_init(zh);
	//int modbits;

	/* first check cheap cases */
#if 0
	//if (LIntCmp (1, x) <= 0) { /* x = 0 or 1 */
	if (mpz_cmp_ui(x, 1) <= 0) { /* x = 0 or 1 */
		// LCpy (z_in, x);
		mpz_set(z_in, x);
		return 1;
	}
#endif
	/* since the exponent is non-0, no other special case needed,
	 * since the following code is correct (though sub-optimal) anyway
	 */

	//modbits = NBITS(n);
	//expbits = NBITS(y);

	// TODO modbits notwendig?
	//int modbits = mpz_sizeinbase(n, 2);
	expbits = mpz_sizeinbase(y, 2);

	timing = 0;

	/*LCpy (&yh, x);
	  LInitNumber(&zh,nbits,0);
	  LInt2Long (1, &zh);*/

	mpz_set(yh, x);
	mpz_init_set_ui(zh, 1);
	for (i=0; i<expbits; i++) {
		// if (LGetBit (y, i)) {
		if (mpz_tstbit(y, i)) {
			timing += /*calc_timing (&zh, &yh);*/ LITTimeModMult (zh, yh, n);
			// LModMult (&zh, &yh, &zh, n);
			mpz_mul(zh, zh, yh);
			mpz_mod(zh, zh, n);
		} else {
			/* zh = zh */
		}
		timing += LITTimeModSquare (yh, n);
		/*(calc_timing (&yh, &yh)+1)/2;*/ /* square is cheaper */
		// LModSquare (&yh, &yh, n);
		mpz_powm_ui(yh, yh, 2, n);
	}
	/* copy out result */
	// LCpy (z_in, &zh);
	mpz_set(z_in, zh);

	mpz_clear(yh);
	mpz_clear(zh);

	return timing;
}

// unsigned long LITTimeModExp (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n)
unsigned long LITTimeModExp (mpz_t x, mpz_t y, mpz_t n)
{
  unsigned long timing;

  int i, expbits;
  // longnum yh;
  // longnum zh;
  mpz_t yh;
  mpz_t zh;
	
	mpz_init(yh);
	mpz_init(zh);
  //int modbits;

  /* first check cheap cases */
#if 0
	//if (LIntCmp (1, x) <= 0) { /* x = 0 or 1 */
  if (mpz_cmp_ui(x, 1) <= 0) { /* x = 0 or 1 */
    // LCpy (z_in, x);
		mpz_set(z_in, x);
    return 1;
  }
#endif
  /* since the exponent is non-0, no other special case needed,
   * since the following code is correct (though sub-optimal) anyway
   */

  /*modbits = NBITS(n);
  expbits = NBITS(y);*/
	// TODO modbits notwendig?
	//int modbits = mpz_sizeinbase(n ,2);
	expbits = mpz_sizeinbase(y, 2);

  timing = 0;

  /* LCpy (&yh, x);
  LInitNumber(&zh,nbits,0);
  LInt2Long (1, &zh);*/

	mpz_set(yh, x);
	mpz_init_set_ui(zh, 1);	

  for (i=0; i<expbits; i++) {
    // if (LGetBit (y, i)) {
		if (mpz_tstbit (y, i)) {
      timing += /*calc_timing (&zh, &yh);*/ LITTimeModMult (zh, yh, n);
      // LModMult (&zh, &yh, &zh, n);
			mpz_mul(zh, zh, yh);
			mpz_mod(zh, zh, n);
    } else {
      /* zh = zh */
    }
    timing += LITTimeModSquare (yh, n);
    /*(calc_timing (&yh, &yh)+1)/2;*/ /* square is cheaper */
    // LModSquare (&yh, &yh, n);
		mpz_powm_ui(yh, yh, 2, n);
  }
  return timing;
}

// TODO wozu braucht man n?
// unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n)
unsigned long LITTimeModMult (mpz_t x, mpz_t y, mpz_t n)
{
  return calc_timing (x, y);
}

// unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n)
unsigned long LITTimeModSquare (mpz_t x, mpz_t n)
{
  return (calc_timing (x, x) + 1) / 2;
}
