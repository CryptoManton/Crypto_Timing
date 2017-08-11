/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptoanalyse"                               *
 **                                                           *
 ** Versuch 4: Kocher-Timing-Attack                           *
 **                                                           *
 **************************************************************
 **
 ** timdaemon.c: Timing-Daemon
 **/

/* Dieser Source ist nur zur Ansicht fuer die Funktionsweise des Daemonen */

#include <stdio.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#include "network.h"

#include <gmp.h>
#include "texp.h"

#include "timing.h"
#include "praktikum.h"

// static longnum n;
static mpz_t n;
static int x;

#define MAXWEIGHT 25

void handle_connection (Connection con, const char *peer, const char *now)
{
	char tmps[33];
	unsigned char mdc[16];
	unsigned long tmp;
	int genexp = 1;
	// longnum y;
	mpz_t y;
	struct message in, out;
	int l;
	struct timeval t;
	struct tms t_times;

	mpz_init(y);

	out.type = SC_Modulus;
	mpz_get_str(out.body.sc_modulus.n, 16, n);
	fprintf (stderr, "-> %s: SC_Modulus\n", peer);
	fflush (stderr);
	Transmit (con, &out, sizeof (out));
	while (1) {
		if ((l=Receive (con, &in, sizeof (in))) != sizeof (in)) {
			if (! l) {
				fprintf (stderr, "<- %s: connection closed\n", peer);
			} else {
				fprintf (stderr, "<- %s: receive %d instead of %lu\n", peer, l, sizeof(in));
			}
			fflush (stderr);
			return;
		}
		if (genexp) {
			MD5_CTX c;
			fprintf (stderr, "-- %s: Generating new exponent\n", peer);
			fflush (stderr);

			/* XXX Zufaelligen Exponenten erzeugen ... */

			genexp = 0;
		}
		mpz_t out_z, in_x, in_y;
		mpz_init(out_z);
		mpz_init(in_x);
		mpz_init(in_y);
		switch (in.type) {
			case CS_Exp:
				/* fprintf (stderr, "<- %s: CS_Exp\n", peer); */
				mpz_set_str(out_z, out.body.sc_exp_r.z, 16);
				mpz_set_str(in_x, in.body.cs_exp.x, 16);
				out.body.sc_exp_r.timing = LITModExp (out_z, in_x, y, n);
				out.type = SC_ExpResp;
				break;
			case CS_Key:
				fprintf (stderr, "<- %s: CS_Key ", peer);
				memcpy (&out.body.sc_key_r.y, &y, sizeof (y));
				out.type = SC_KeyResp;
				mpz_set_str(in_y, in.body.cs_key.y, 16);
				out.body.sc_key_r.ok = ! mpz_cmp(y, in_y); // LCompare (&y, &in.body.cs_key.y);
				if (! out.body.sc_key_r.ok) fprintf (stderr, "not ");
				fprintf (stderr, "ok\n");
				fflush (stderr);
				genexp = 1;
				break;
			default:
				fprintf (stderr, "<- %s: unknown type %d\n", peer, in.type);
				fflush (stderr);
				return;
		}
		mpz_clears(out_z, in_x, in_y, NULL);
		/* fprintf (stderr, "-> %s: response\n", peer); */
		Transmit (con, &out, sizeof (out));
	}
}

int main(int argc, char **argv)
{
	Connection con;
	PortConnection port;
	const char *name = TIMING_NAME;
	const char *other, *now;

	struct sigaction sa;
	sa.sa_handler= SIG_IGN;
	sa.sa_flags=SA_NOCLDWAIT;
	/* this old code produced a warning 
		struct sigaction sa = {
		SIG_IGN, 0, 0, SA_NOCLDWAIT
		};*/

	x = time(0);

	sigaction (SIGCHLD, &sa, 0);

	{
		char buf[1024];
		FILE *x;

		const char *datafile, *root;
		if (!(root=getenv("PRAKTROOT"))) root="";
		datafile =concatstrings(root,"/loesungen/timing/modulus.hex",NULL);
		x = fopen (datafile, "r");
		if (! x) { perror (datafile); exit (2); }
		fgets (buf, 1024, x);
		fclose (x);
		// LHex2Long (buf, &n);
		mpz_set_str(n , buf, 16);
	}

	/***************  Globales Port eröffnen  ***************/
	if (!(port=OpenPort(name))) {
		fprintf(stderr,"TIMING_DAEMON: Kann das Dämon-Port \"%s\" nicht erzeugen: %s\n",name,NET_ErrorText());
		exit(20);
	}

	/******************* Hauptschleife **********************/
	while (1) {

		/**************  Auf Verbindung auf dem Port warten  ****************/
		if (!(con=WaitAtPort(port))) {
			fprintf(stderr,"TIMING_DAEMON: WaitAtPort ging schief: %s\n",NET_ErrorText());
			exit(20);
		}
		other = PeerName(port);
		now = Now();

		fprintf (stderr, "Connect from %s: %s\n", other, now);
		fflush (stderr);

		x += time(0);
		handle_connection (con, other, now);
		DisConnect (con);
	}

	return 0;
}
