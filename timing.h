/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** timing.h: Message-Struktur zwischen Daemon und Client
**/

#define TIMING_NAME "Timing_Daemon"
#define STRINGLEN 5122

struct message {
  enum { SC_Modulus, CS_Exp, SC_ExpResp, CS_Key, SC_KeyResp } type;
  union {
    struct sc_modulus {
      // longnum n;
			char n[STRINGLEN];
    } sc_modulus;
    struct cs_exp {
      // longnum x;
			char x[STRINGLEN];
    } cs_exp;
    struct sc_exp_r {
      // longnum z;
			char z[STRINGLEN];
      unsigned long timing;
    } sc_exp_r;
    struct cs_key {
      // longnum y;
			char y[STRINGLEN];
    } cs_key;
    struct sc_key_r {
      // longnum y; /* Der echte Exponent */
			char y[STRINGLEN];		/* Der echte Exponent */
      int ok;    /* 1 = Richtig geraten, 0 = falsch */
    } sc_key_r;
  } body;
};
