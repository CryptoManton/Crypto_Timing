/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** daem_acc.c: Routinen für den Zugriff auf den Dämonen
**/
#include <stdio.h>
#include <stdlib.h>

#include "network.h"

#include <gmp.h>

#include "timing.h"

#include "daemon.h"

static Connection c = 0;
static struct message in, out;

// void connect_daemon (longnum_ptr n)
void connect_daemon (mpz_t n)
{
  char *name = MakeNetName ("Timing");
  if (c) {
    fprintf (stderr, "Warning: connect_daemon: already connected\n");
    disc_daemon ();
  }
  c = ConnectTo (name, TIMING_NAME);
  if (! c) {
    fprintf (stderr, "Connect failed: %s\n", NET_ErrorText());
    exit (1);
  }
  if (Receive (c, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Error in Receive in connect_daemon\n");
    exit (1);
  }
  if (in.type != SC_Modulus) {
    fprintf (stderr, "Unexpected message type (expected SC_Modulus)\n");
    exit (1);
  }
  mpz_set_str(n, in.body.sc_modulus.n, 16);
}

// unsigned long exp_daemon (longnum_ptr z, const_longnum_ptr x)
unsigned long exp_daemon (mpz_t z, mpz_t x)
{
  if (! c) {
    fprintf (stderr, "exp_daemon called without connection\n");
    exit (1);
  }
  out.type = CS_Exp;
  mpz_get_str(out.body.cs_exp.x, 16, x);
  Transmit (c, &out, sizeof (out));
  if (Receive (c, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Error in Receive in exp_daemon\n");
    exit (1);
  }
  if (in.type != SC_ExpResp) {
    fprintf (stderr, "Unexpected message type (expected SC_ExpResp)\n");
    exit (1);
  }
  mpz_set_str(z, in.body.sc_exp_r.z, 16);
  return in.body.sc_exp_r.timing;
}

// int key_daemon (longnum_ptr y_ok, const_longnum_ptr y_trial)
int key_daemon (mpz_t y_ok, mpz_t y_trial)
{
  if (! c) {
    fprintf (stderr, "key_daemon called without connection\n");
    exit (1);
  }
  out.type = CS_Key;
  mpz_get_str(out.body.cs_key.y, 16, y_trial);
  Transmit (c, &out, sizeof (out));
  if (Receive (c, &in, sizeof (in)) != sizeof (in)) {
    fprintf (stderr, "Error in Receive in key_daemon\n");
    exit (1);
  }
  if (in.type != SC_KeyResp) {
    fprintf (stderr, "Unexpected message type (expected SC_KeyResp)\n");
    exit (1);
  }
  mpz_set_str(y_ok, in.body.sc_key_r.y, 16);
  return in.body.sc_key_r.ok;
}

void disc_daemon (void)
{
  DisConnect (c);
  c = 0;
}
