/********************************************************************************************
* SHA3-derived functions: SHA3-256, SHA3-512, SHAKE, and cSHAKE
*
* Based on the public domain implementation in crypto_hash/keccakc512/simple/
* from http://bench.cr.yp.to/supercop.html by Ronny Van Keer
* and the public domain "TweetFips202" implementation from https://twitter.com/tweetfips202
* by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe
*
* See NIST Special Publication 800-185 for more information:
* http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
*
* Updated by John Underhill, December 24, 2017
*********************************************************************************************/

#include "sha3.h"

/* Internal */

static uint64_t load64(const uint8_t* a)
{
	uint64_t r = 0;
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		r |= (uint64_t)a[i] << (8 * i);
	}

	return r;
}

static uint64_t rotl64(const uint64_t x, uint32_t shift)
{
	return (x << shift) | (x >> (64 - shift));
}

static void store64(uint8_t* a, uint64_t x)
{
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		a[i] = x & 0xFF;
		x >>= 8;
	}
}

static void keccak_absorb(uint64_t* state, size_t rate, const uint8_t* input, size_t inplen, uint8_t domain)
{
	uint8_t msg[200];
	size_t i;

	while (inplen >= rate)
	{
		for (i = 0; i < rate / 8; ++i)
		{
			state[i] ^= load64(input + (8 * i));
		}

		keccak_permute(state);

		inplen -= rate;
		input += rate;
	}

	for (i = 0; i < inplen; ++i)
	{
		msg[i] = input[i];
	}

	msg[inplen] = domain;

	for (i = inplen + 1; i < rate; ++i)
	{
		msg[i] = 0;
	}

	msg[rate - 1] |= 128;

	for (i = 0; i < rate / 8; ++i)
	{
		state[i] ^= load64(msg + (8 * i));
	}
}

static void keccak_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state, size_t rate)
{
	size_t i;

	while (nblocks > 0)
	{
		keccak_permute(state);

		for (i = 0; i < (rate >> 3); i++)
		{
			store64(output + 8 * i, state[i]);
		}

		output += rate;
		nblocks--;
	}
}

/* SHA3 */

void keccak_permute(uint64_t* state)
{
	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	/* round 1 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 2 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 3 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 4 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 5 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 6 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 7 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 8 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 9 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 10 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 11 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 12 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 13 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 14 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 15 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 16 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 17 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 18 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 19 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 20 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 21 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 22 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 23 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 24 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

void sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHA3_256_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	keccak_absorb(state, SHA3_256_RATE, message, msglen, SHA3_DOMAIN);
	keccak_squeezeblocks(hash, 1, state, SHA3_256_RATE);

	for (i = 0; i < 32; i++)
	{
		output[i] = hash[i];
	}
}

void sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHA3_512_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	keccak_absorb(state, SHA3_512_RATE, message, msglen, SHA3_DOMAIN);
	keccak_squeezeblocks(hash, 1, state, SHA3_512_RATE);

	for (i = 0; i < 64; i++)
	{
		output[i] = hash[i];
	}
}

void sha3_blockupdate(uint64_t* state, size_t rate, const uint8_t* message, size_t msgoffset, size_t msglen)
{
	size_t i;

	while (msglen >= rate)
	{
		for (i = 0; i < rate / 8; ++i)
		{
			state[i] ^= load64(message + msgoffset + (8 * i));
		}

		keccak_permute(state);

		msglen -= rate;
		message += rate;
	}
}

void sha3_finalize(uint64_t* state, size_t rate, const uint8_t* message, size_t msgoffset, size_t msglen, uint8_t* output)
{
	uint8_t msg[200];
	size_t i;
	size_t len;

	sha3_blockupdate(state, rate, message, msgoffset, msglen);

	msglen = (msglen % rate);

	for (i = 0; i < msglen; ++i)
	{
		msg[i] = message[i + msgoffset];
	}

	msg[msglen] = SHA3_DOMAIN;

	for (i = msglen + 1; i < rate; ++i)
	{
		msg[i] = 0;
	}

	msg[rate - 1] |= 128;

	for (i = 0; i < rate / 8; ++i)
	{
		state[i] ^= load64(msg + (8 * i));
	}

	keccak_permute(state);
	len = (((200 - rate) / 2) / 8);

	for (i = 0; i < len; i++)
	{
		store64(output, state[i]);
		output += 8;
	}
}

/* SHAKE */

void shake128(uint8_t* output, size_t outlen, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outlen / SHAKE128_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHAKE128_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	keccak_absorb(state, SHAKE128_RATE, seed, seedlen, SHAKE_DOMAIN);
	keccak_squeezeblocks(output, nblocks, state, SHAKE128_RATE);

	output += (nblocks * SHAKE128_RATE);
	outlen -= (nblocks * SHAKE128_RATE);

	if (outlen != 0)
	{
		keccak_squeezeblocks(hash, 1, state, SHAKE128_RATE);

		for (i = 0; i < outlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void shake128_absorb(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, SHAKE128_RATE, seed, seedlen, SHAKE_DOMAIN);
}

void shake128_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state)
{
	keccak_squeezeblocks(output, nblocks, state, SHAKE128_RATE);
}

void shake256(uint8_t* output, size_t outlen, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outlen / SHAKE256_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[SHAKE256_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	keccak_absorb(state, SHAKE256_RATE, seed, seedlen, SHAKE_DOMAIN);
	keccak_squeezeblocks(output, nblocks, state, SHAKE256_RATE);

	output += (nblocks * SHAKE256_RATE);
	outlen -= (nblocks * SHAKE256_RATE);

	if (outlen != 0)
	{
		keccak_squeezeblocks(hash, 1, state, SHAKE256_RATE);

		for (i = 0; i < outlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void shake256_absorb(uint64_t* state, const uint8_t* seed, size_t seedlen)
{
	keccak_absorb(state, SHAKE256_RATE, seed, seedlen, SHAKE_DOMAIN);
}

void shake256_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state)
{
	keccak_squeezeblocks(output, nblocks, state, SHAKE256_RATE);
}

/* cSHAKE */

void cshake128_simple(uint8_t* output, size_t outlen, uint16_t cstm, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outlen / CSHAKE128_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE128_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	cshake128_simple_absorb(state, cstm, seed, seedlen);
	keccak_squeezeblocks(output, nblocks, state, CSHAKE128_RATE);

	output += (nblocks * CSHAKE128_RATE);
	outlen -= (nblocks * CSHAKE128_RATE);

	if (outlen != 0)
	{
		keccak_squeezeblocks(hash, 1, state, CSHAKE128_RATE);

		for (i = 0; i < outlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake128_simple_absorb(uint64_t* state, uint16_t cstm, const uint8_t* seed, size_t seedlen)
{
	/* Note: This function doesn't align exactly to cSHAKE (SP800-185 3.2), which should produce
	SHAKE output if S and N = zero (sort of a customized custom-SHAKE function).
	Padding is hard-coded as the first 32 bits, plus 16 bits of fixed N, and 16 bits of counter.
	The short integer optimizes this function for a digest counter configuration */

	uint8_t sep[8];
	sep[0] = 0x01; /* bytepad */
	sep[1] = 0xA8;
	sep[2] = 0x01;
	sep[3] = 0x00;
	sep[4] = 0x01;
	sep[5] = 0x10; /* bitlen of cstm */
	sep[6] = cstm & 0xFF;
	sep[7] = cstm >> 8;

	state[0] = load64(sep);

	/* transform the domain string */
	keccak_permute(state);

	/* absorb the state */
	keccak_absorb(state, CSHAKE128_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake128_simple_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state)
{
	keccak_squeezeblocks(output, nblocks, state, CSHAKE128_RATE);
}

void cshake256_simple(uint8_t* output, size_t outlen, uint16_t cstm, const uint8_t* seed, size_t seedlen)
{
	size_t nblocks = outlen / CSHAKE256_RATE;
	uint64_t state[SHA3_STATESIZE];
	uint8_t hash[CSHAKE256_RATE];
	size_t i;

	for (i = 0; i < SHA3_STATESIZE; ++i)
	{
		state[i] = 0;
	}

	cshake256_simple_absorb(state, cstm, seed, seedlen);
	keccak_squeezeblocks(output, nblocks, state, CSHAKE256_RATE);

	output += (nblocks * CSHAKE256_RATE);
	outlen -= (nblocks * CSHAKE256_RATE);

	if (outlen != 0)
	{
		keccak_squeezeblocks(hash, 1, state, CSHAKE256_RATE);

		for (i = 0; i < outlen; i++)
		{
			output[i] = hash[i];
		}
	}
}

void cshake256_simple_absorb(uint64_t* state, uint16_t cstm, const uint8_t* seed, size_t seedlen)
{
	uint8_t sep[8];
	sep[0] = 0x01; /* bytepad */
	sep[1] = 0x88;
	sep[2] = 0x01;
	sep[3] = 0x00;
	sep[4] = 0x01;
	sep[5] = 0x10; /* bitlen of cstm */
	sep[6] = cstm & 0xFF;
	sep[7] = cstm >> 8;

	state[0] = load64(sep);

	/* transform the domain string */
	keccak_permute(state);

	/* absorb the state */
	keccak_absorb(state, CSHAKE256_RATE, seed, seedlen, CSHAKE_DOMAIN);
}

void cshake256_simple_squeezeblocks(uint8_t* output, size_t nblocks, uint64_t* state)
{
	keccak_squeezeblocks(output, nblocks, state, CSHAKE256_RATE);
}
