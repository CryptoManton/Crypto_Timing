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


int main (void)
{
  connect_daemon (n); /* Mit dem Daemonen verbinden und den Modulus
                        * abholen */

  /* XXX Aufgabe: mit exp_daemon () Samples generieren und y_trial berechnen */
  mpz_t z, x0;
  mpz_init (z);
  mpz_init (x0);
  mpz_init (y_trial);
  
  //berechne Hamming-Gewicht des Exponenten mit Basis (x) 1
   mpz_set_ui(x0, 1);

  // unsigned long LITTimeModSquare (const_longnum_ptr x, const_longnum_ptr n);
  unsigned long potTime =   EXPBITS * LITTimeModSquare(x0, n);
  
  // unsigned long LITTimeModMult (const_longnum_ptr x, const_longnum_ptr y, const_longnum_ptr n);
  unsigned long multTime = LITTimeModMult(x0, x0, n);
  unsigned long expTime = exp_daemon(z, x0);
  unsigned long hamWeight = (expTime - potTime) / multTime; 
  
   printf ("Hamming weight: %lu \n", hamWeight);
  
  unsigned long timings[NUMSAMPLES];
  mpz_t samples[NUMSAMPLES];
  mpz_t tmp;
  mpz_init(tmp);
  
  //Gesamttiming der Multiplikationen
  unsigned long tM = 0;
  
  //entnehme Proben und ziehe Timings der Quadrierungen ab 
  //-> erhalte Liste mit Proben und Timings der Multiplikationen
  for (unsigned int i = 0; i < NUMSAMPLES; i++) {
	mpz_init(samples[i]);
	mpz_set_ui(tmp, i);
	
    timings[i] = exp_daemon(samples[i], tmp);
	
	//Timing für Quadrierung
	unsigned long tmpPot = EXPBITS * LITTimeModSquare(tmp, n);
	//printf ("Timings: %d %lu \n", i, timings[i]);
	timings[i] -= tmpPot;

	tM += timings[i];
	
	//printf ("Timings: %d %lu \n", i, timings[i]);
  }
  
  
  mpz_t xi, zi;
  mpz_init(xi);
  mpz_init(zi);
  
  
  unsigned long tMult = 0;
  
  //Iteriere über alle Bit des Exponenten 
  for (unsigned int i = 0; i < EXPBITS; i++) {

  unsigned long t0 = 0;
  unsigned long t1 = 0; 
 
   //Berechne Korrelation für i-tes Bit bei allen Samples
	for (unsigned int j = 0; j < NUMSAMPLES; j++) {
		/*
		  x0 = x
	      z0 = 1
		*/
		
	  // 0-tes Bit des Exponenten
	  if (i == 0) {
		mpz_set_ui(xi, mpz_get_ui(samples[j]));
		mpz_set_ui(zi, 1);
		
		tMult = LITTimeModMult(xi,zi,n);
	  } 
	  
	  //Summe über alle samples
		t0 += tM - (hamWeight * expected_timing * tMult);
		t1 += tM - (tMult + (hamWeight-1) * expected_timing * tMult);
		
	
		//printf ("Exponent %d, Sample %d, Summe t0: %lu \n", i, j, t0);
		//printf ("Exponent %d, Sample %d, Summe t1: %lu \n", i, j, t1);
	}
	
	unsigned long fak1 = mpz_get_ui(zi);
	mpz_t f1;
	mpz_init(f1);
	mpz_set_ui(f1, fak1);
	
	unsigned long fak2 = mpz_get_ui(xi);
	mpz_t f2;
	mpz_init(f2);
	mpz_set_ui(f2, fak2);
	
	
	if (t1 < t0) {
	printf("1");
		/*
		i-tes Bit des Exponenten ist 1
			xi+1 = xi^2
			zi+1 = zi * xi
		*/
		
		
		
		mpz_mul(xi, f2, f2); 
		mpz_mul(zi, f1, f2); 
	
	
		mpz_set_ui(y_trial, mpz_get_ui(y_trial)| (1 << i)) ;
		
		tM -= tMult;
		hamWeight--;
		
	
	} else {
	printf("0");
		/* 
		i-tes Bit des Exponenten ist 0
			xi+1 = xi^2
			zi+1 = zi 
		*/
		mpz_mul(xi, f2, f2); 
		
	}
	
	tMult = LITTimeModMult(xi,zi,n);
	
	
  
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
  exit (0);
}
