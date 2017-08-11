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

#include <gmp.h>
#include "texp.h"

#include "daemon.h"


#define EXPBITS 128 /* Anzahl der Bits im Exponent */

//longnum n; /* Modulus */
//longnum y_trial; /* Hier soll der geheime Exponent y berechnet werden */
//longnum y_ok; /* Tatsaechlicher geheimer Exponent (vom Daemon) */*/
mpz_t n; /* Modulus */
mpz_t y_trial; /* Hier soll der geheime Exponent y berechnet werden */
mpz_t y_ok; /* Tatsaechlicher geheimer Exponent (vom Daemon) */
int ok; /* war der Exponent richtig? */
int debug = 1;

const unsigned long expected_timing = (1<<18);
/* Erwartungswert fuer den Zeitaufwand einer Multiplikation */


int main (void)
{
  connect_daemon (n); /* Mit dem Daemonen verbinden und den Modulus
                        * abholen */

  /* XXX Aufgabe: mit exp_daemon () Samples generieren und y_trial berechnen */
  /* We need all exp-results and their durations */
  mpz_t *squares;
  mpz_t *durations;
  mpz_t z, x, y;

  for (int i = 0; i < EXPBITS; i++) {
    mpz_set_ui(squares[i], 0);
    mpz_set_ui(durations[i], 0);
  }
  mpz_set_ui(x, 1);
  mpz_set_ui(y, 0);
  for (int i = 0; i < EXPBITS; i++) {
    mpz_set_ui(z, 0);
    mpz_set_ui(durations[i], LITModExp(z, x, y, n));
    mpz_set_ui(squares[i], mpz_get_ui(z));
    if (mpz_get_ui(y) == 0) {
      mpz_set_ui(y, 1);
    } else {
      mpz_set_ui(y, mpz_get_ui(y) * 2);
    }
  }

  if (debug) {
    for (int i = 0; i < EXPBITS; i++) {
      mpz_set_ui(y, 0);
            // z = x ^ y in some seconds.
      printf ("%s = %s ^ %s in %s s.\n", mpz_get_str(NULL, 16, squares[i]), mpz_get_str(NULL, 16, x), mpz_get_str(NULL, 16, y), mpz_get_str(NULL, 16, durations[i]));
    }
    if (mpz_get_ui(y) == 0) {
      mpz_set_ui(y, 1);
    } else {
      mpz_set_ui(y, mpz_get_ui(y) * 2);
    }
  }

  /* Suche Gewicht von y */
  //z = 0;
  //unsigned long time_x = 0;
  //time_x = exp_daemon(z, x);


  // clear all
  /*for (int i = 0; i < EXPBITS; i++) {
    mpz_clear(squares[i]);
    mpz_clear(durations[i]);
  }
  mpz_clear(z);
  mpz_clear(x);
  mpz_clear(y);*/

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
