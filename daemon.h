/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptoanalyse"                               *
**                                                           *
** Versuch 4: Kocher-Timing-Attack                           *
**                                                           *
**************************************************************
**
** daemon.h: Header-File fuer den Zugriff auf den Timing-Daemonen
**/
/* connect_daemon verbindet sich mit dem Daemon und gibt auch
 * im Parameter n den verwendeten Modulus zurueck.
 */
// void connect_daemon (longnum_ptr n);
void connect_daemon (mpz_t n);
/* exp_daemon laesst den Daemonen den Wert x verschluesseln
 * (d.h. x^y mod n bestimmen, mit unbekanntem, aber festem y)
 * Return: in z das Ergebnis, als Returnwert das Timing
 */
// unsigned long exp_daemon (longnum_ptr z, const_longnum_ptr x);
unsigned long exp_daemon (mpz_t z, mpz_t x);
/* key_daemon:
 * Prueft, ob y_trial dem vom Daemon verwendeten y entspricht.
 * Returnwert: != 0: y_trial war richtig
 *                0: y_trial war falsch
 * in y_ok wird der vom Server verwendete Wert fuer y
 * zurueckgegeben.
 * Wenn danach weitere exp_daemon-Aufrufe geschehen, wird
 * ein neues y gewaehlt!
 */
// int key_daemon (longnum_ptr y_ok, const_longnum_ptr y_trial);
int key_daemon (mpz_t y_ok, mpz_t y_trial);
/* disc_daemon schliesst die Verbindung zum Daemon */
void disc_daemon (void);
