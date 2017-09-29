/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** attack.c: Timing-Attacke Rahmenprogramm
**/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <gmp.h>
#include "texp.h"

#include "daemon.h"

/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** attack.c: Timing-Attacke Rahmenprogramm
**/
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <gmp.h>
#include "texp.h"

#include "daemon.h"


#define EXPBITS 128 /* Anzahl der Bits im Exponent */
#define NUMSAMPLES 3000 /* Anzahl der genommenen Samples */

//longnum n; /* Modulus */
//longnum y_trial; /* Hier soll der geheime Exponent y berechnet werden */
//longnum y_ok; /* Tatsaechlicher geheimer Exponent (vom Daemon) */*/
mpz_t n; /* Modulus */
mpz_t y_trial; /* Hier soll der geheime Exponent y berechnet werden */
mpz_t y_ok; /* Tatsaechlicher geheimer Exponent (vom Daemon) */
int ok; /* war der Exponent richtig? */

const unsigned long expected_timing = (1<<18);
/* Erwartungswert fuer den Zeitaufwand einer Multiplikation */
/*
int calc(mpz_t x, mpz_t z, mpz_t y) {
	mpz_t x0, z0;
	mpz_init (x0);
	mpz_init (z0);
	
	mpz_set(x0, x);
	mpz_set_ui(z0, 1);
	
	for (unsigned int i = 0; i < 128;i++) {
	
			if (mpz_tstbit(y, i)) {
				mpz_mul(z, z, x0);
			
			} else {
				mpz_mul_ui(z, z, 1);
			}
			
			mpz_mul(x0, x0, x0);
	
	
	}
	
	return mpz_get_ui(z0);

}
*/
unsigned long calcHamming(mpz_t x0, mpz_t z, mpz_t n) {
 //berechne Hamming-Gewicht des Exponenten mit Basis (x) 1
   mpz_set_ui(x0, 1);

  // unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n);
  unsigned long potTime =   EXPBITS * LITTimeModSquare(x0, n);
  
  // unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
  unsigned long multTime = LITTimeModMult(x0, x0, n);
  printf("Time for 1 mult:  %lu \n", multTime);
  unsigned long expTime = exp_daemon(z, x0);
  unsigned long hamWeight = (expTime - potTime) / multTime; 
  
   printf ("Hamming weight: %lu \n", hamWeight);
   
   return hamWeight;
}

/*
unsigned long calcHammingTest(mpz_t x0, mpz_t z, mpz_t n, mpz_t y) {
 //berechne Hamming-Gewicht des Exponenten mit Basis (x) 1
   mpz_set_ui(x0, 1);

  // unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n);
  unsigned long potTime =   EXPBITS * LITTimeModSquare(x0, n);
   printf ("potTime: %lu \n", potTime);
  
  // unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
  unsigned long multTime = LITTimeModMult(x0, x0, n);
   printf ("multTime: %lu \n", multTime);
  unsigned long expTime = calc(z, x0, y);
   printf ("expTime: %lu \n", expTime);
  unsigned long hamWeight = (expTime - potTime) / multTime; 
  
   printf ("Hamming weight Test: %lu \n", hamWeight);
   
   return hamWeight;
}

*/
int main (void)
{
  connect_daemon (n); /* Mit dem Daemonen verbinden und den Modulus
                        * abholen */

  /* XXX Aufgabe: mit exp_daemon () Samples generieren und y_trial berechnen */
  mpz_t z, x0;
  mpz_init (z);
  mpz_init (x0);
  mpz_init (y_trial);
  
  mpz_t zwei;
	mpz_init(zwei);
	mpz_set_ui(zwei, 2);
  
	unsigned long hamWeight = calcHamming(x0, z, n);
	
  
  unsigned long timings[NUMSAMPLES];
  mpz_t samples[NUMSAMPLES];
  mpz_t values[NUMSAMPLES];
  mpz_t tmp;
  mpz_init(tmp);
  unsigned long tmpTiming;
  

  //entnehme Proben und ziehe Timings der Quadrierungen ab 
  //-> erhalte zu den Proben gehörige Listen mit Timings der Multiplikationen
  mpz_t tmpSample, tmpValue;
  mpz_init(tmpSample);
  mpz_init(tmpValue);
  for (unsigned int i = 0; i < NUMSAMPLES; i++) {
	mpz_init(samples[i]);
	mpz_init(values[i]);
	
	mpz_set_ui(values[i], i);
	mpz_set_ui(samples[i], 1);

    timings[i] = exp_daemon(tmpSample, values[i]);
	
	//Timing für Quadrierung
	
	mpz_set(tmpValue, values[i]);
	
	
	for (unsigned int j = 0; j < EXPBITS; j++) {
	//gmp_printf("tmpNum %Zd \n", tmpValue);
		timings[i] -= LITTimeModSquare(tmpValue, n);
		mpz_mul(tmpValue,tmpValue,tmpValue);
		mpz_mod(tmpValue,tmpValue,n);
	}
	
	//	gmp_printf("AAA sample: %Zd value: %Zd \n", samples[i], values[i]);
  }

  unsigned long tMult = 0;
  unsigned long t0 = 0;
  unsigned long t1 = 0; 
  //Iteriere über alle Bit des Exponenten 
  for (unsigned int i = 0; (i < EXPBITS) && (hamWeight > 0); i++) {
   //Berechne Korrelation für i-tes Bit über alle Samples
   t0 = 0;
   t1 = 0;
	for (unsigned int j = 0; j < NUMSAMPLES; j++) {
		  
		//   gmp_printf("ZZZ sample: %Zd value: %Zd \n", samples[j], values[j]);
	  tMult = LITTimeModMult(samples[j], values[j],n);
	  //Summe über alle samples
	 // printf("tMult %Zd \n", tMult);
	  
	 
	 // printf("Timing: %lu tMult %lu hamWeight %d \n", timings[j], tMult, hamWeight);
		t0 += (unsigned long) labs(((signed long) timings[j]) -  ((signed long)(hamWeight * expected_timing)));
		t1 += (unsigned long) labs(((signed long) timings[j]) - ((signed long)(tMult + (hamWeight-1) * expected_timing)));
		
	//	gmp_printf("BBB sample: %Zd value: %Zd \n", samples[j], values[j]);
	}
		
		//printf("t0 %lu t1 %lu \n", t0, t1);
	if (t1 < t0) {
	printf("1");
	//printf("Bit %d gesetzt! \n", i);
		/*
		i-tes Bit des Exponenten ist 1
			zi+1 = zi * xi 
			
			x - values
			z - samples
		*/	
		
		for (unsigned int j = 0; j < NUMSAMPLES; j++) {
			mpz_mul(samples[j], samples[j], values[j]);
		    mpz_mod(samples[j], samples[j], n);
			
			tMult = LITTimeModMult(samples[j], values[j], n);
			timings[j] -= tMult;
		}
		
		mpz_setbit(y_trial, i);
		hamWeight--;	
	} else {
	printf("0");
		/* 
		i-tes Bit des Exponenten ist 0
			zi+1 = zi
			
		*/
		
	}
	
	//xi+1 = xi^2
	for (unsigned int j = 0; j < NUMSAMPLES; j++) {
			mpz_mul(values[j], values[j], values[j]);
		    mpz_mod(values[j], values[j], n);
			
		//	gmp_printf("CCC sample: %Zd value: %Zd \n", samples[j], values[j]);
	}
	
  }
  printf("\n");

  // printf ("Berechneter Exponent: %s\n", LLong2Hex (&y_trial, 0, 1, 1));
	printf ("Berechneter Exponent: %s\n", mpz_get_str(NULL, 16, y_trial));

  ok = key_daemon (y_ok, y_trial);
  printf ("Das war %s\n", ok?"richtig":"falsch");
  if (! ok) {
    // printf ("Richtig war: %s\n", LLong2Hex (&y_ok, 0, 1, 1));
		printf ("Richtig war: %s\n", mpz_get_str(NULL, 16, y_ok));
  }
  disc_daemon (); /* Verbindung zum Daemon beenden */
  /*
  	mpz_t xTest, yTest, zTest;
	mpz_init(xTest);
	mpz_init(yTest);
	mpz_init(zTest);
	
	mpz_set(xTest, x0);
	mpz_set_ui(yTest, 3);
	
	calcHammingTest(xTest, zTest, n, yTest);
	*/
  exit (0);
}
