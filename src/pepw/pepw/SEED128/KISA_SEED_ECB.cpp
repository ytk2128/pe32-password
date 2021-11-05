/*******************************************************************************
* Created  June, 1999
* Modified  Dec, 2013
* FILE:         KISA_SEED_ECB.c
*
* DESCRIPTION: Core routines for the enhanced SEED
* 
*******************************************************************************/

/******************************* Include files ********************************/

#include "KISA_SEED_ECB.h"


/******************** Macros for Encryption and Decryption ********************/

#define GetB0(A)  ( (BYTE)((A)    ) )
#define GetB1(A)  ( (BYTE)((A)>> 8) )
#define GetB2(A)  ( (BYTE)((A)>>16) )
#define GetB3(A)  ( (BYTE)((A)>>24) )

// Round function F and adding output of F to L.
// L0, L1 : left input values at each round
// R0, R1 : right input values at each round
// K : round keys at each round
#define SEED_KeySched(L0, L1, R0, R1, K) {             \
    T0 = R0 ^ (K)[0];                              \
    T1 = R1 ^ (K)[1];                              \
    T1 ^= T0;                                      \
    T1 = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^         \
         SS2[GetB2(T1)] ^ SS3[GetB3(T1)];          \
    T0 = (T0 + T1) & 0xffffffff;                   \
    T0 = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^         \
         SS2[GetB2(T0)] ^ SS3[GetB3(T0)];          \
    T1 = (T1 + T0) & 0xffffffff;                   \
    T1 = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^         \
         SS2[GetB2(T1)] ^ SS3[GetB3(T1)];          \
    T0 = (T0 + T1) & 0xffffffff;                   \
    L0 ^= T0; L1 ^= T1;                            \
}

/********************************* Encryption *********************************/

void SEED_Encrypt (
		BYTE *pbData, 				// [in,out]	data to be encrypted
		DWORD *pdwRoundKey)			// [in]			round keys for encryption
{
	DWORD L0, L1, R0, R1;		// Iuput/output values at each rounds
	DWORD T0, T1;				// Temporary variables for round function F
	DWORD *K = pdwRoundKey;		// Pointer of round keys

// Set up input values for first round
	L0 = ((DWORD)pbData[3] << 24) | ((DWORD)pbData[2] << 16) | ((DWORD)pbData[1] << 8) | ((DWORD)pbData[0]);
	L1 = ((DWORD)pbData[7] << 24) | ((DWORD)pbData[6] << 16) | ((DWORD)pbData[5] << 8) | ((DWORD)pbData[4]);
	R0 = ((DWORD)pbData[11] << 24) | ((DWORD)pbData[10] << 16) | ((DWORD)pbData[9] << 8) | ((DWORD)pbData[8]);
	R1 = ((DWORD)pbData[15] << 24) | ((DWORD)pbData[14] << 16) | ((DWORD)pbData[13] << 8) | ((DWORD)pbData[12]);
    
// Reorder for big endian 
// Because SEED use little endian order in default
#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif

    SEED_KeySched(L0, L1, R0, R1, K   ); 	// Round 1
    SEED_KeySched(R0, R1, L0, L1, K+ 2); 	// Round 2
    SEED_KeySched(L0, L1, R0, R1, K+ 4); 	// Round 3
    SEED_KeySched(R0, R1, L0, L1, K+ 6); 	// Round 4
    SEED_KeySched(L0, L1, R0, R1, K+ 8); 	// Round 5
    SEED_KeySched(R0, R1, L0, L1, K+10); 	// Round 6
    SEED_KeySched(L0, L1, R0, R1, K+12); 	// Round 7
    SEED_KeySched(R0, R1, L0, L1, K+14); 	// Round 8
    SEED_KeySched(L0, L1, R0, R1, K+16); 	// Round 9
    SEED_KeySched(R0, R1, L0, L1, K+18); 	// Round 10
    SEED_KeySched(L0, L1, R0, R1, K+20); 	// Round 11
    SEED_KeySched(R0, R1, L0, L1, K+22); 	// Round 12
    SEED_KeySched(L0, L1, R0, R1, K+24); 	// Round 13
    SEED_KeySched(R0, R1, L0, L1, K+26); 	// Round 14
    SEED_KeySched(L0, L1, R0, R1, K+28); 	// Round 15
    SEED_KeySched(R0, R1, L0, L1, K+30); 	// Round 16
	

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif

// Copying output values from last round to pbData
	pbData[0] = (BYTE)((R0)&0xFF);
	pbData[1] = (BYTE)((R0>>8)&0xFF);
	pbData[2] = (BYTE)((R0>>16)&0xFF);
	pbData[3] = (BYTE)((R0>>24)&0xFF);

	pbData[4] = (BYTE)((R1)&0xFF);
	pbData[5] = (BYTE)((R1>>8)&0xFF);
	pbData[6] = (BYTE)((R1>>16)&0xFF);
	pbData[7] = (BYTE)((R1>>24)&0xFF);

	pbData[8] = (BYTE)((L0)&0xFF);
	pbData[9] = (BYTE)((L0>>8)&0xFF);
	pbData[10] = (BYTE)((L0>>16)&0xFF);
	pbData[11] = (BYTE)((L0>>24)&0xFF);

	pbData[12] = (BYTE)((L1)&0xFF);
	pbData[13] = (BYTE)((L1>>8)&0xFF);
	pbData[14] = (BYTE)((L1>>16)&0xFF);
	pbData[15] = (BYTE)((L1>>24)&0xFF);
}


/********************************* Decryption *********************************/

// Same as encrypt, except that round keys are applied in reverse order
void SEED_Decrypt (
		BYTE *pbData, 				// [in,out]	data to be decrypted
		DWORD *pdwRoundKey)			// [in]			round keys for decryption
{
	DWORD L0, L1, R0, R1;		// Iuput/output values at each rounds
	DWORD T0, T1;				// Temporary variables for round function F
	DWORD *K = pdwRoundKey;		// Pointer of round keys

// Set up input values for first round
	L0 = ((DWORD)pbData[3] << 24) | ((DWORD)pbData[2] << 16) | ((DWORD)pbData[1] << 8) | ((DWORD)pbData[0]);
	L1 = ((DWORD)pbData[7] << 24) | ((DWORD)pbData[6] << 16) | ((DWORD)pbData[5] << 8) | ((DWORD)pbData[4]);
	R0 = ((DWORD)pbData[11] << 24) | ((DWORD)pbData[10] << 16) | ((DWORD)pbData[9] << 8) | ((DWORD)pbData[8]);
	R1 = ((DWORD)pbData[15] << 24) | ((DWORD)pbData[14] << 16) | ((DWORD)pbData[13] << 8) | ((DWORD)pbData[12]);

// Reorder for big endian 
#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif
	//printf("%08X %08X %08X %08X\n",L0,L1,R0,R1);

    SEED_KeySched(L0, L1, R0, R1, K+30); 	// Round 1
    SEED_KeySched(R0, R1, L0, L1, K+28); 	// Round 2 
    SEED_KeySched(L0, L1, R0, R1, K+26); 	// Round 3 
    SEED_KeySched(R0, R1, L0, L1, K+24); 	// Round 4 
    SEED_KeySched(L0, L1, R0, R1, K+22); 	// Round 5 
    SEED_KeySched(R0, R1, L0, L1, K+20); 	// Round 6 
    SEED_KeySched(L0, L1, R0, R1, K+18); 	// Round 7 
    SEED_KeySched(R0, R1, L0, L1, K+16); 	// Round 8 
    SEED_KeySched(L0, L1, R0, R1, K+14); 	// Round 9 
    SEED_KeySched(R0, R1, L0, L1, K+12); 	// Round 10
    SEED_KeySched(L0, L1, R0, R1, K+10); 	// Round 11
    SEED_KeySched(R0, R1, L0, L1, K+ 8); 	// Round 12
    SEED_KeySched(L0, L1, R0, R1, K+ 6); 	// Round 13
    SEED_KeySched(R0, R1, L0, L1, K+ 4); 	// Round 14
    SEED_KeySched(L0, L1, R0, R1, K+ 2); 	// Round 15
    SEED_KeySched(R0, R1, L0, L1, K+ 0); 	// Round 16

#ifdef LITTLE_ENDIAN
    L0 = EndianChange(L0);
    L1 = EndianChange(L1);
    R0 = EndianChange(R0);
    R1 = EndianChange(R1);
#endif

// Copy output values from last round to pbData
	pbData[0] = (BYTE)((R0)&0xFF);
	pbData[1] = (BYTE)((R0>>8)&0xFF);
	pbData[2] = (BYTE)((R0>>16)&0xFF);
	pbData[3] = (BYTE)((R0>>24)&0xFF);

	pbData[4] = (BYTE)((R1)&0xFF);
	pbData[5] = (BYTE)((R1>>8)&0xFF);
	pbData[6] = (BYTE)((R1>>16)&0xFF);
	pbData[7] = (BYTE)((R1>>24)&0xFF);

	pbData[8] = (BYTE)((L0)&0xFF);
	pbData[9] = (BYTE)((L0>>8)&0xFF);
	pbData[10] = (BYTE)((L0>>16)&0xFF);
	pbData[11] = (BYTE)((L0>>24)&0xFF);

	pbData[12] = (BYTE)((L1)&0xFF);
	pbData[13] = (BYTE)((L1>>8)&0xFF);
	pbData[14] = (BYTE)((L1>>16)&0xFF);
	pbData[15] = (BYTE)((L1>>24)&0xFF);
}


/************************ Constants for Key schedule **************************/

//		KC0 = golden ratio; KCi = ROTL(KCi-1, 1) 
#define KC0     0x9e3779b9UL
#define KC1     0x3c6ef373UL
#define KC2     0x78dde6e6UL
#define KC3     0xf1bbcdccUL
#define KC4     0xe3779b99UL
#define KC5     0xc6ef3733UL
#define KC6     0x8dde6e67UL
#define KC7     0x1bbcdccfUL
#define KC8     0x3779b99eUL
#define KC9     0x6ef3733cUL
#define KC10    0xdde6e678UL
#define KC11    0xbbcdccf1UL
#define KC12    0x779b99e3UL
#define KC13    0xef3733c6UL
#define KC14    0xde6e678dUL
#define KC15    0xbcdccf1bUL


/************************** Macros for Key schedule ***************************/

#define RoundKeyUpdate0(K, A, B, C, D, KC) {	\
    T0 = A + C - KC;                            \
    T1 = B + KC - D;                            \
    (K)[0] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^  \
             SS2[GetB2(T0)] ^ SS3[GetB3(T0)];   \
    (K)[1] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^  \
             SS2[GetB2(T1)] ^ SS3[GetB3(T1)];   \
    T0 = A;                                     \
    A = (A>>8) ^ (B<<24);                       \
    B = (B>>8) ^ (T0<<24);                      \
}

#define RoundKeyUpdate1(K, A, B, C, D, KC) {	\
    T0 = A + C - KC;                            \
    T1 = B + KC - D;                            \
    (K)[0] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^  \
             SS2[GetB2(T0)] ^ SS3[GetB3(T0)];   \
    (K)[1] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^  \
             SS2[GetB2(T1)] ^ SS3[GetB3(T1)];   \
    T0 = C;                                     \
    C = (C<<8) ^ (D>>24);                       \
    D = (D<<8) ^ (T0>>24);                      \
}


/******************************** Key Schedule ********************************/

void SEED_KeySchedKey(
		DWORD *pdwRoundKey,			// [out]	round keys for encryption or decryption
		BYTE *pbUserKey)			// [in]		secret user key
{
	DWORD A, B, C, D;				// Iuput/output values at each rounds
	DWORD T0, T1;					// Temporary variable
	DWORD *K = pdwRoundKey;			// Pointer of round keys

// Set up input values for Key Schedule	
	A = ((DWORD)pbUserKey[3] << 24) | ((DWORD)pbUserKey[2] << 16) | ((DWORD)pbUserKey[1] << 8) | ((DWORD)pbUserKey[0]);
	B = ((DWORD)pbUserKey[7] << 24) | ((DWORD)pbUserKey[6] << 16) | ((DWORD)pbUserKey[5] << 8) | ((DWORD)pbUserKey[4]);
	C = ((DWORD)pbUserKey[11] << 24) | ((DWORD)pbUserKey[10] << 16) | ((DWORD)pbUserKey[9] << 8) | ((DWORD)pbUserKey[8]);
	D = ((DWORD)pbUserKey[15] << 24) | ((DWORD)pbUserKey[14] << 16) | ((DWORD)pbUserKey[13] << 8) | ((DWORD)pbUserKey[12]);
	 
// Reorder for big endian 
#ifndef BIG_ENDIAN
	A = EndianChange(A);
	B = EndianChange(B);
	C = EndianChange(C);
	D = EndianChange(D);
#endif

// i-th round keys( K_i,0 and K_i,1 ) are denoted as K[2*(i-1)] and K[2*i-1], respectively
    RoundKeyUpdate0(K   , A, B, C, D, KC0 );	// K_1,0 and K_1,1
    RoundKeyUpdate1(K+ 2, A, B, C, D, KC1 );	// K_2,0 and K_2,1
    RoundKeyUpdate0(K+ 4, A, B, C, D, KC2 );	// K_3,0 and K_3,1
    RoundKeyUpdate1(K+ 6, A, B, C, D, KC3 );	// K_4,0 and K_4,1
    RoundKeyUpdate0(K+ 8, A, B, C, D, KC4 );	// K_5,0 and K_5,1
    RoundKeyUpdate1(K+10, A, B, C, D, KC5 );	// K_6,0 and K_6,1
    RoundKeyUpdate0(K+12, A, B, C, D, KC6 );	// K_7,0 and K_7,1
    RoundKeyUpdate1(K+14, A, B, C, D, KC7 );	// K_8,0 and K_8,1
    RoundKeyUpdate0(K+16, A, B, C, D, KC8 );	// K_9,0 and K_9,1
    RoundKeyUpdate1(K+18, A, B, C, D, KC9 );	// K_10,0 and K_10,1
    RoundKeyUpdate0(K+20, A, B, C, D, KC10);	// K_11,0 and K_11,1
    RoundKeyUpdate1(K+22, A, B, C, D, KC11);	// K_12,0 and K_12,1
    RoundKeyUpdate0(K+24, A, B, C, D, KC12);	// K_13,0 and K_13,1
    RoundKeyUpdate1(K+26, A, B, C, D, KC13);	// K_14,0 and K_14,1
    RoundKeyUpdate0(K+28, A, B, C, D, KC14);	// K_15,0 and K_15,1

    T0 = A + C - KC15;
    T1 = B - D + KC15;
    K[30] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^	// K_16,0
           SS2[GetB2(T0)] ^ SS3[GetB3(T0)];
    K[31] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^	// K_16,1
           SS2[GetB2(T1)] ^ SS3[GetB3(T1)];

}

/*********************************** END **************************************/