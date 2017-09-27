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
#define NUMSAMPLES 50 /* Anzahl der genommenen Samples */

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
  mpz_t tmp;
  mpz_init(tmp);
  unsigned long tmpTiming;
  
  //Gesamttiming der Multiplikationen
  unsigned long tM = 0;
  
  //entnehme Proben und ziehe Timings der Quadrierungen ab 
  //-> erhalte Liste mit Proben und Timings der Multiplikationen
  for (unsigned int i = 0; i < NUMSAMPLES; i++) {
	mpz_init(samples[i]);
	mpz_set_ui(tmp, i);
	
    timings[i] = exp_daemon(samples[i], tmp);
	
	//Timing für Quadrierung
	mpz_t tmpTmp;
	mpz_init(tmpTmp);
	mpz_set(tmpTmp, tmp);
	
	
	unsigned long tmpPot = 0;
	
	for (unsigned int j = 0; j < EXPBITS; j++) {
		tmpPot += LITTimeModSquare(tmpTmp, n);
		LITModExp(tmpTmp, tmpTmp, zwei, n);
	}
	
	tmpTiming = timings[i] - tmpPot;
	printf ("Timings[%d]:  %lu, %lu, %lu \n", i, timings[i], tmpPot, tmpTiming);
	timings[i] -= tmpPot;
	
	//tM - Gesamttiming der Multiplikationen
	tM += timings[i];
	
  }
  printf ("Gesamttiming der Multiplikationen %lu \n", tM);
  unsigned long timeMultHW = tM / hamWeight;
    printf ("Gesamttiming der Multiplikationen / HW %lu \n", timeMultHW);
  
  mpz_t xi, zi;
  mpz_init(xi);
  mpz_init(zi);
  unsigned long tMult = 0;
  unsigned long t0 = 0;
  unsigned long t1 = 0; 
  //Iteriere über alle Bit des Exponenten 
  for (unsigned int i = 0; i < EXPBITS; i++) {
   //Berechne Korrelation für i-tes Bit bei allen Samples
	for (unsigned int j = 0; j < NUMSAMPLES; j++) {
		  
	  // 0-tes Bit des Exponenten
	  //x0 = x
	  //z0 = 1  
	  if (i == 0) {
		mpz_set(xi, samples[j]);
		mpz_set_ui(zi, 1);
	  }
	  tMult = LITTimeModMult(xi,zi,n);
	  //Summe über alle samples
		t0 += tM - (hamWeight * expected_timing * tMult);
		t1 += tM - (tMult + (hamWeight-1) * expected_timing * tMult);
	}
		
	if (t1 < t0) {
	printf("1");
		/*
		i-tes Bit des Exponenten ist 1
			zi+1 = zi * xi
			xi+1 = xi^2
		*/	
		mpz_mul(zi, xi, zi);
		mpz_mod(zi, zi, n);
		LITModExp(xi, xi, zwei, n);
		
		tM -= tMult;
		hamWeight--;	
	} else {
	printf("0");
		/* 
		i-tes Bit des Exponenten ist 0
			zi+1 = zi 
			xi+1 = xi^2
			
		*/
		LITModExp(xi, xi, zwei, n);	
	}
	
  }
  printf("\n");

 
  
  
  
  
  //mpz_set_ui(y_trial, mpz_get_ui(y_trial)| (1 << i)) ;

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
